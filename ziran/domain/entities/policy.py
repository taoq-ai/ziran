"""Organizational security policy models.

Defines the structure for custom security policies that organizations
can use to enforce compliance requirements on scan results.

A **Policy** is a collection of **PolicyRule** instances that express
thresholds, constraints, and requirements.  The **PolicyEngine** evaluates
a :class:`CampaignResult` against these rules and produces a
:class:`PolicyVerdict` listing violations and warnings.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

# ── Rule types ───────────────────────────────────────────────────────


class RuleType(StrEnum):
    """Supported policy rule types."""

    MIN_TRUST_SCORE = "min_trust_score"
    """Final trust score must be ≥ threshold."""

    MAX_CRITICAL_VULNS = "max_critical_vulnerabilities"
    """Maximum number of critical-severity findings allowed."""

    MAX_HIGH_VULNS = "max_high_vulnerabilities"
    """Maximum number of high-severity findings allowed."""

    MAX_TOTAL_VULNS = "max_total_vulnerabilities"
    """Maximum total vulnerabilities across all severities."""

    REQUIRED_CATEGORIES = "required_categories"
    """Attack categories that *must* appear in the scan."""

    REQUIRED_OWASP = "required_owasp"
    """OWASP LLM categories that must be covered (tested)."""

    FORBIDDEN_FINDINGS = "forbidden_findings"
    """Combinations of category + severity that auto-fail the policy."""

    MAX_CRITICAL_PATHS = "max_critical_paths"
    """Maximum number of critical attack paths in the graph."""


# ── Severity of a rule violation ─────────────────────────────────────

RuleSeverity = Literal["error", "warning", "info"]


# ── Core models ──────────────────────────────────────────────────────


class PolicyRule(BaseModel):
    """A single evaluatable rule within a policy."""

    rule_type: RuleType
    description: str = ""
    severity: RuleSeverity = "error"
    parameters: dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    """A named collection of security rules.

    Policies are typically loaded from YAML files and evaluated against
    :class:`~koan.domain.entities.phase.CampaignResult` instances.
    """

    id: str
    name: str
    description: str = ""
    version: str = "1.0"
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyViolation(BaseModel):
    """One rule that was not satisfied."""

    rule_type: RuleType
    rule_description: str = ""
    severity: RuleSeverity = "error"
    message: str
    actual_value: Any = None
    threshold: Any = None


class PolicyVerdict(BaseModel):
    """Outcome of evaluating a policy against campaign results."""

    policy_id: str
    policy_name: str
    passed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)
    warnings: list[PolicyViolation] = Field(default_factory=list)
    info: list[PolicyViolation] = Field(default_factory=list)
    summary: str = ""

    @property
    def error_count(self) -> int:
        return len(self.violations)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)
