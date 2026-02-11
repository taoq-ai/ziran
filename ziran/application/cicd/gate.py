"""Quality-gate evaluator for CI/CD pipelines.

Evaluates a :class:`~koan.domain.entities.phase.CampaignResult`
against a :class:`~koan.domain.entities.ci.QualityGateConfig`
and produces a :class:`~koan.domain.entities.ci.GateResult`
that determines whether a pipeline should pass or fail.

Usage::

    gate = QualityGate()                                  # default config
    gate = QualityGate(QualityGateConfig(min_trust_score=0.8))
    result = gate.evaluate(campaign_result)
    sys.exit(result.exit_code)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from ziran.domain.entities.ci import (
    FindingCount,
    GateResult,
    GateStatus,
    GateViolation,
    QualityGateConfig,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.phase import CampaignResult


class QualityGate:
    """Evaluate campaign results against CI/CD quality thresholds.

    Args:
        config: Gate configuration.  Uses sensible defaults when
            omitted (zero tolerance for critical findings).
    """

    def __init__(self, config: QualityGateConfig | None = None) -> None:
        self.config = config or QualityGateConfig()

    # ── Loading helpers ──────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: Path) -> QualityGate:
        """Build a gate from a YAML configuration file."""
        if not path.exists():
            msg = f"Gate config not found: {path}"
            raise FileNotFoundError(msg)

        with path.open() as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            msg = f"Invalid gate config \u2014 expected mapping, got {type(data).__name__}"
            raise ValueError(msg)

        return cls(QualityGateConfig.model_validate(data))

    # ── Evaluation ───────────────────────────────────────────────────

    def evaluate(self, result: CampaignResult) -> GateResult:
        """Run all quality checks and return the gate outcome."""
        violations: list[GateViolation] = []
        counts = self._count_findings(result)

        # 1. Trust-score check
        if (
            self.config.min_trust_score > 0
            and result.final_trust_score < self.config.min_trust_score
        ):
            violations.append(
                GateViolation(
                    rule="min_trust_score",
                    message=(
                        f"Trust score {result.final_trust_score:.2f} is below "
                        f"minimum {self.config.min_trust_score:.2f}"
                    ),
                    severity="critical",
                )
            )

        # 2. Critical-findings check (legacy shortcut)
        if (
            self.config.max_critical_findings >= 0
            and counts.critical > self.config.max_critical_findings
        ):
            violations.append(
                GateViolation(
                    rule="max_critical_findings",
                    message=(
                        f"Found {counts.critical} critical finding(s), "
                        f"max allowed is {self.config.max_critical_findings}"
                    ),
                    severity="critical",
                )
            )

        # 3. Per-severity threshold checks
        for sev in ("critical", "high", "medium", "low"):
            threshold = self.config.severity_thresholds.max_for(sev)  # type: ignore[arg-type]
            actual = getattr(counts, sev)
            if threshold >= 0 and actual > threshold:
                violations.append(
                    GateViolation(
                        rule=f"severity_threshold_{sev}",
                        message=(f"Found {actual} {sev} finding(s), max allowed is {threshold}"),
                        severity=sev,  # type: ignore[arg-type]
                    )
                )

        # 4. Policy-violation check
        if self.config.fail_on_policy_violation and not result.success:
            # `result.success` is True when any critical path exists,
            # meaning the *agent* is vulnerable.  For gating purposes
            # we treat that as a failure.
            pass  # already covered by findings; kept for explicit gate
        if self.config.fail_on_policy_violation and result.success:
            violations.append(
                GateViolation(
                    rule="policy_violation",
                    message="Critical attack paths were found in the campaign",
                    severity="critical",
                )
            )

        status = GateStatus.FAILED if violations else GateStatus.PASSED
        summary = self._build_summary(status, violations, counts, result)

        return GateResult(
            status=status,
            violations=violations,
            finding_counts=counts,
            trust_score=result.final_trust_score,
            summary=summary,
        )

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _count_findings(result: CampaignResult) -> FindingCount:
        """Aggregate successful (vulnerability) findings by severity."""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for raw in result.attack_results:
            ar: dict[str, Any] = raw if isinstance(raw, dict) else raw.model_dump()  # type: ignore[union-attr]
            if ar.get("successful"):
                sev = ar.get("severity", "medium")
                if sev in counts:
                    counts[sev] += 1

        return FindingCount(**counts)

    @staticmethod
    def _build_summary(
        status: GateStatus,
        violations: list[GateViolation],
        counts: FindingCount,
        result: CampaignResult,
    ) -> str:
        """Build a concise human-readable summary."""
        parts = [
            f"Gate: {status.value.upper()}",
            f"Trust: {result.final_trust_score:.2f}",
            f"Findings: {counts.total} "
            f"(C:{counts.critical} H:{counts.high} M:{counts.medium} L:{counts.low})",
        ]
        if violations:
            parts.append(f"Violations: {len(violations)}")
        return " | ".join(parts)
