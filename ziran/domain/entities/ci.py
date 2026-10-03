"""CI/CD integration domain models.

Defines the quality-gate configuration and evaluation results
used when ZIRAN runs inside a CI/CD pipeline (GitHub Actions,
GitLab CI, Jenkins, etc.).
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

if TYPE_CHECKING:
    from collections.abc import Sequence

#: Severity levels — duplicated here to avoid circular-import issues
#: while keeping the Pydantic model self-contained at runtime.
Severity = Literal["low", "medium", "high", "critical"]

FindingKind = Literal["attack", "chain"]
SuppressionState = Literal["new", "suppressed", "regressed"]

_Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_NonBlank = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def attack_fingerprint(target_agent: str, vector_id: str, category: str) -> str:
    """Identity of a successful attack result (shared with the web findings page)."""
    return _sha256(f"{target_agent}:{vector_id}:{category}")


def chain_fingerprint(target_agent: str, vulnerability_type: str) -> str:
    """Identity of a dangerous tool chain. The tools are deliberately NOT part of the key."""
    return _sha256(f"chain:{target_agent}:{vulnerability_type}")


def attack_content_hash(severity: str, category: str) -> str:
    """Material content of an attack finding (never evidence, responses or prompts)."""
    return _sha256(_canonical({"category": category, "severity": severity}))


def chain_content_hash(tools: Sequence[str], risk_level: str) -> str:
    """Material content of a chain finding: tools in recorded order and risk level."""
    return _sha256(_canonical({"risk_level": risk_level, "tools": list(tools)}))


class GateStatus(StrEnum):
    """Outcome of a quality-gate evaluation."""

    PASSED = "passed"
    FAILED = "failed"


class SeverityThresholds(BaseModel):
    """Maximum allowed findings by severity before the gate fails.

    Setting a value to ``0`` means zero tolerance for that severity.
    Setting it to ``-1`` (or omitting it) means *unlimited* — the gate
    never fails for that severity alone.
    """

    critical: int = Field(default=0, description="Max critical findings allowed (-1 = unlimited)")
    high: int = Field(default=-1, description="Max high findings allowed (-1 = unlimited)")
    medium: int = Field(default=-1, description="Max medium findings allowed (-1 = unlimited)")
    low: int = Field(default=-1, description="Max low findings allowed (-1 = unlimited)")

    def max_for(self, severity: Severity) -> int:
        """Return the threshold for the given severity string."""
        return int(getattr(self, severity))


class QualityGateConfig(BaseModel):
    """Configuration for the CI/CD quality gate.

    Controls when a pipeline should be marked as *failed* based
    on scan results.

    Example YAML::

        min_trust_score: 0.7
        max_critical_findings: 0
        fail_on_policy_violation: true
        severity_thresholds:
          critical: 0
          high: 3
          medium: -1
          low: -1
    """

    min_trust_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum trust score to pass (0.0 = disabled).",
    )
    max_critical_findings: int = Field(
        default=0,
        description="Maximum critical findings before failing (-1 = unlimited).",
    )
    fail_on_policy_violation: bool = Field(
        default=True,
        description="Fail the gate when the policy engine reports a violation.",
    )
    severity_thresholds: SeverityThresholds = Field(
        default_factory=SeverityThresholds,
    )
    require_owasp_coverage: bool = Field(
        default=False,
        description="Fail if no OWASP mapping is present on findings.",
    )


class FindingCount(BaseModel):
    """Aggregated finding counts by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class GateViolation(BaseModel):
    """A single reason the quality gate failed."""

    rule: str
    message: str
    severity: Severity = "high"


class SuppressionEntry(BaseModel):
    """One accepted finding in ``.ziran/suppressions.yaml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: _Hex64
    content_hash: _Hex64
    reason: _NonBlank
    added_by: _NonBlank
    expires: date | None = None  # valid through this date

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


class SuppressionFile(BaseModel):
    """The committed suppressions file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    entries: list[SuppressionEntry] = Field(default_factory=list)


class GateFinding(BaseModel):
    """One finding the gate counts, with its suppression classification."""

    kind: FindingKind
    index: int  # position in CampaignResult.attack_results / .dangerous_tool_chains
    label: str  # vector_id (attack) or vulnerability_type (chain)
    severity: str  # raw value; only low|medium|high|critical are counted
    fingerprint: str
    content_hash: str
    state: SuppressionState = "new"
    reason: str = ""  # reason of the matching entry when state == "suppressed"


class GateResult(BaseModel):
    """Outcome of evaluating a campaign result against the quality gate."""

    status: GateStatus
    violations: list[GateViolation] = Field(default_factory=list)
    finding_counts: FindingCount = Field(default_factory=FindingCount)
    trust_score: float = Field(ge=0.0, le=1.0, default=1.0)
    summary: str = ""
    findings: list[GateFinding] = Field(default_factory=list)
    new_findings: int = 0
    suppressed_findings: int = 0
    regressed_findings: int = 0
    suppressions_applied: bool = False

    def suppressed_attacks(self) -> dict[int, str]:
        """attack_results index -> entry reason, for every suppressed attack result."""
        return {
            f.index: f.reason
            for f in self.findings
            if f.kind == "attack" and f.state == "suppressed"
        }

    @property
    def passed(self) -> bool:
        return self.status == GateStatus.PASSED

    @property
    def exit_code(self) -> int:
        """Return a process exit code suitable for CI (0 = pass, 1 = fail)."""
        return 0 if self.passed else 1
