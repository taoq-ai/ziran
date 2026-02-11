"""CI/CD integration domain models.

Defines the quality-gate configuration and evaluation results
used when KOAN runs inside a CI/CD pipeline (GitHub Actions,
GitLab CI, Jenkins, etc.).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

#: Severity levels — duplicated here to avoid circular-import issues
#: while keeping the Pydantic model self-contained at runtime.
Severity = Literal["low", "medium", "high", "critical"]


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


class GateResult(BaseModel):
    """Outcome of evaluating a campaign result against the quality gate."""

    status: GateStatus
    violations: list[GateViolation] = Field(default_factory=list)
    finding_counts: FindingCount = Field(default_factory=FindingCount)
    trust_score: float = Field(ge=0.0, le=1.0, default=1.0)
    summary: str = ""

    @property
    def passed(self) -> bool:
        return self.status == GateStatus.PASSED

    @property
    def exit_code(self) -> int:
        """Return a process exit code suitable for CI (0 = pass, 1 = fail)."""
        return 0 if self.passed else 1
