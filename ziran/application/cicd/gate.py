"""Quality-gate evaluator for CI/CD pipelines.

Evaluates a :class:`~ziran.domain.entities.phase.CampaignResult`
against a :class:`~ziran.domain.entities.ci.QualityGateConfig`
and produces a :class:`~ziran.domain.entities.ci.GateResult`
that determines whether a pipeline should pass or fail.

Usage::

    gate = QualityGate()                                  # default config
    gate = QualityGate(QualityGateConfig(min_trust_score=0.8))
    result = gate.evaluate(campaign_result)
    sys.exit(result.exit_code)
"""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

import yaml

from ziran.domain.entities.ci import (
    FindingCount,
    GateFinding,
    GateResult,
    GateStatus,
    GateViolation,
    QualityGateConfig,
    Severity,
    SuppressionEntry,
    SuppressionFile,
    attack_content_hash,
    attack_fingerprint,
    chain_content_hash,
    chain_fingerprint,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.phase import CampaignResult

_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")


def load_suppressions(path: Path) -> SuppressionFile:
    """Read and validate a suppressions YAML file.

    Raises:
        FileNotFoundError: the file does not exist.
        ValueError: not a mapping, or schema validation failed.
        yaml.YAMLError: the file is not valid YAML.
    """
    with path.open() as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        msg = f"Invalid suppressions file — expected mapping, got {type(data).__name__}"
        raise ValueError(msg)

    return SuppressionFile.model_validate(data)


def _composition_node_id(chain: dict[str, Any]) -> str:
    """Graph node id of a chain finding.

    Mirrors ``AttackKnowledgeGraph.add_chain_finding``; pinned by a drift test.
    """
    tools = [str(t) for t in chain.get("tools", [])]
    return f"composition::{chain.get('vulnerability_type', 'unknown')}::{'->'.join(tools)}"


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

    def evaluate(
        self,
        result: CampaignResult,
        suppressions: SuppressionFile | None = None,
        *,
        today: date | None = None,
    ) -> GateResult:
        """Run all quality checks and return the gate outcome.

        With *suppressions*, findings matching a non-expired entry (fingerprint and
        content hash) are left out of the thresholds; a fingerprint match with a
        different content hash is a regression; expired entries are violations.
        """
        violations: list[GateViolation] = []
        findings = self._findings(result)
        expired: list[SuppressionEntry] = []
        if suppressions is not None:
            findings, expired = self._classify(findings, suppressions, today or date.today())
        counts = self._tally(findings)

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
        for sev in _SEVERITIES:
            threshold = self.config.severity_thresholds.max_for(sev)
            actual = getattr(counts, sev)
            if threshold >= 0 and actual > threshold:
                violations.append(
                    GateViolation(
                        rule=f"severity_threshold_{sev}",
                        message=(f"Found {actual} {sev} finding(s), max allowed is {threshold}"),
                        severity=sev,
                    )
                )

        # 4. Policy-violation check
        if self.config.fail_on_policy_violation:
            policy: str | None = None
            if suppressions is not None:
                policy = self._policy_message(result, findings)
            elif result.success:
                # `result.success` is True when the agent is vulnerable — a critical
                # attack path, a phase vulnerability, or a critical tool-composition
                # chain.  For gating purposes we treat that as a failure.
                policy = "Critical attack paths or tool-composition chains were found"
            if policy:
                violations.append(
                    GateViolation(rule="policy_violation", message=policy, severity="critical")
                )

        # 5. Regressed suppressions (finding order)
        violations.extend(
            GateViolation(
                rule="suppression_regressed",
                message=(
                    f"Suppressed finding {f.fingerprint} changed: content hash is now "
                    f"{f.content_hash}; review it and update the entry"
                ),
                severity="high",
            )
            for f in findings
            if f.state == "regressed"
        )

        # 6. Expired suppressions (file order)
        violations.extend(
            GateViolation(
                rule="suppression_expired",
                message=(
                    f"Suppression {e.fingerprint} expired on {e.expires} "
                    f"(reason: {e.reason}); renew or remove the entry"
                ),
                severity="high",
            )
            for e in expired
        )

        status = GateStatus.FAILED if violations else GateStatus.PASSED
        summary = self._build_summary(status, violations, counts, result)
        new, sup, reg = (
            sum(f.state == state for f in findings) for state in ("new", "suppressed", "regressed")
        )
        if suppressions is not None:
            summary += f" | Suppressions: new {new}, suppressed {sup}, regressed {reg}"

        return GateResult(
            status=status,
            violations=violations,
            finding_counts=counts,
            trust_score=result.final_trust_score,
            summary=summary,
            findings=findings,
            new_findings=new,
            suppressed_findings=sup,
            regressed_findings=reg,
            suppressions_applied=suppressions is not None,
        )

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _policy_message(result: CampaignResult, findings: list[GateFinding]) -> str | None:
        """Policy rule with a suppressions file loaded (spec 046 FR-008).

        Fails on any unsuppressed finding, any critical path not backed by a
        suppressed finding, or any unbacked phase vulnerability. Backed ids: the
        ``vector_id`` of a suppressed attack; the composition node id and the
        ``vulnerability_type`` of a suppressed chain. A path is backed when its
        last node is a backed id or it equals a suppressed chain's
        ``graph_path`` (the trace-analysis shape).
        """
        suppressed = [f for f in findings if f.state == "suppressed"]
        chains = [result.dangerous_tool_chains[f.index] for f in suppressed if f.kind == "chain"]
        backed = {f.label for f in suppressed} | {_composition_node_id(c) for c in chains}
        backed_paths = {tuple(str(n) for n in c.get("graph_path") or ()) for c in chains}
        unsuppressed = len(findings) - len(suppressed)
        paths = sum(
            1
            for p in result.critical_paths
            if not p or (p[-1] not in backed and tuple(p) not in backed_paths)
        )
        vulns = len({v for ph in result.phases_executed for v in ph.vulnerabilities_found} - backed)
        if not (unsuppressed or paths or vulns):
            return None
        return (
            "Unsuppressed findings or unbacked critical paths were found "
            f"({unsuppressed} unsuppressed finding(s), {paths} unbacked critical path(s), "
            f"{vulns} unbacked phase vulnerability(ies))"
        )

    @staticmethod
    def _count_findings(result: CampaignResult) -> FindingCount:
        """Aggregate findings by severity.

        Counts both detector-confirmed vulnerabilities *and* tool-composition
        chains — a critical composition (e.g. ``search_database ->
        send_email_report``) is a finding the gate must act on, not a side note.
        """
        return QualityGate._tally(QualityGate._findings(result))

    @staticmethod
    def _findings(result: CampaignResult) -> list[GateFinding]:
        """Every finding the gate counts: successful attacks, then tool chains."""
        findings: list[GateFinding] = []
        for i, raw in enumerate(result.attack_results):
            ar: dict[str, Any] = raw if isinstance(raw, dict) else raw.model_dump()
            if not ar.get("successful"):
                continue
            vector_id = str(ar.get("vector_id", ""))
            category = str(ar.get("category", "unknown"))
            severity = str(ar.get("severity", "medium"))
            findings.append(
                GateFinding(
                    kind="attack",
                    index=i,
                    label=vector_id,
                    severity=severity,
                    fingerprint=attack_fingerprint(result.target_agent, vector_id, category),
                    content_hash=attack_content_hash(severity, category),
                )
            )

        # Tool-composition chains are first-class findings.
        for i, chain in enumerate(result.dangerous_tool_chains):
            vt = str(chain.get("vulnerability_type", "unknown"))
            severity = str(chain.get("risk_level", "medium"))
            tools = [str(t) for t in chain.get("tools", [])]
            findings.append(
                GateFinding(
                    kind="chain",
                    index=i,
                    label=vt,
                    severity=severity,
                    fingerprint=chain_fingerprint(result.target_agent, vt),
                    content_hash=chain_content_hash(tools, severity),
                )
            )
        return findings

    @staticmethod
    def _tally(findings: list[GateFinding]) -> FindingCount:
        """Count non-suppressed findings by severity (other severities ignored)."""
        counts = dict.fromkeys(_SEVERITIES, 0)
        for f in findings:
            if f.state != "suppressed" and f.severity in counts:
                counts[f.severity] += 1
        return FindingCount(**counts)

    @staticmethod
    def _classify(
        findings: list[GateFinding], suppressions: SuppressionFile, today: date
    ) -> tuple[list[GateFinding], list[SuppressionEntry]]:
        """Mark findings new / suppressed / regressed; also return the expired entries."""
        active = [e for e in suppressions.entries if not e.expired(today)]
        expired = [e for e in suppressions.entries if e.expired(today)]
        classified: list[GateFinding] = []
        for f in findings:
            same = [e for e in active if e.fingerprint == f.fingerprint]
            match = next((e for e in same if e.content_hash == f.content_hash), None)
            if match is not None:
                f = f.model_copy(update={"state": "suppressed", "reason": match.reason})
            elif same:
                f = f.model_copy(update={"state": "regressed"})
            classified.append(f)
        return classified, expired

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
