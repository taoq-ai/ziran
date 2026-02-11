"""Configuration models for the Static Analyzer.

All regex patterns, check metadata (IDs, severities, messages,
recommendations), and skip-directory rules are expressed as Pydantic
models backed by YAML so organisations can extend or replace them
without code changes.

Example::

    config = StaticAnalysisConfig.default()
    custom = StaticAnalysisConfig.from_yaml(Path("my_rules.yaml"))
    merged = config.merge(custom)
    analyzer = StaticAnalyzer(config=merged)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ── Building blocks ──────────────────────────────────────────────────


class PatternRule(BaseModel):
    """A single regex pattern with associated metadata."""

    pattern: str
    """Regex pattern string (will be compiled at runtime)."""

    description: str = ""
    """Optional human-readable description of what this pattern detects."""


class CheckDefinition(BaseModel):
    """Definition of a static-analysis check.

    Groups one or more regex patterns under a single check ID
    with shared severity, message, and recommendation text.
    """

    check_id: str
    """Unique identifier, e.g. ``SA001``."""

    message: str
    """Short message shown when the check triggers."""

    severity: str
    """One of ``critical``, ``high``, ``medium``, ``low``."""

    recommendation: str = ""
    """Actionable fix guidance."""

    patterns: list[PatternRule] = Field(default_factory=list)
    """Regex patterns — a match on *any* pattern triggers the check."""

    skip_comments: bool = True
    """Whether to skip lines that look like comments / docstrings."""


class DangerousToolCheck(BaseModel):
    """A dangerous-tool pattern with its own description."""

    check_id: str = "SA003"
    pattern: str
    description: str
    severity: str = "high"
    recommendation: str = (
        "Restrict tool permissions and add guardrails. Consider sandboxing or an approval workflow."
    )
    skip_comments: bool = True


class InputValidationCheck(BaseModel):
    """Heuristic check for missing input validation."""

    check_id: str = "SA002"
    message: str = "No input validation detected in tool definitions"
    severity: str = "high"
    recommendation: str = (
        "Add input validation (type checks, length limits, allow-lists) to all tool functions."
    )
    tool_definition_pattern: str = r"(?i)@tool|def\s+\w+.*->.*str"
    """Pattern that identifies tool definitions."""

    validation_pattern: str = (
        r"(?i)(validate|sanitize|strip|len\(|re\.\w+\(|"
        r"if\s+not\s+\w+|raise\s+ValueError)"
    )
    """Pattern that indicates validation is present."""


# ── Top-level config ─────────────────────────────────────────────────


class StaticAnalysisConfig(BaseModel):
    """Full configuration for the Static Analyzer.

    Holds every check definition, pattern, and tunable piece
    so the analyzer is fully data-driven.
    """

    secret_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA001 — Secrets / API keys in source code."""

    dangerous_tool_checks: list[DangerousToolCheck] = Field(default_factory=list)
    """SA003 — Dangerous tool / shell execution patterns."""

    sql_injection_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA009 — SQL injection risk."""

    pii_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA010 — PII exposure risk."""

    hardcoded_cred_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA008 — Hard-coded credentials."""

    verbose_error_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA006 — Verbose error messages."""

    unrestricted_tool_checks: list[CheckDefinition] = Field(default_factory=list)
    """SA007 — Unrestricted / large tool lists."""

    input_validation: InputValidationCheck = Field(
        default_factory=InputValidationCheck,
    )
    """SA002 — No input validation heuristic."""

    skip_directories: list[str] = Field(default_factory=list)
    """Directory names to skip during recursive scans."""

    # ── I/O ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: Path) -> StaticAnalysisConfig:
        """Load configuration from a YAML file."""
        if not path.exists():
            msg = f"Config file not found: {path}"
            raise FileNotFoundError(msg)

        with path.open() as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            msg = f"Invalid config — expected mapping, got {type(data).__name__}"
            raise ValueError(msg)

        return cls.model_validate(data)

    @classmethod
    def default(cls) -> StaticAnalysisConfig:
        """Load the built-in default configuration."""
        default_path = Path(__file__).parent / "default_config.yaml"
        return cls.from_yaml(default_path)

    # ── Merge ────────────────────────────────────────────────────────

    def merge(self, other: StaticAnalysisConfig) -> StaticAnalysisConfig:
        """Merge *other* config into this one (additive).

        Check definitions are merged by ``check_id``; dangerous-tool
        checks by ``pattern``; skip directories are deduplicated.

        Returns:
            A new :class:`StaticAnalysisConfig` with merged data.
        """
        return StaticAnalysisConfig(
            secret_checks=_merge_checks(self.secret_checks, other.secret_checks),
            dangerous_tool_checks=_merge_by_key(
                self.dangerous_tool_checks,
                other.dangerous_tool_checks,
                key=lambda e: e.pattern,
            ),
            sql_injection_checks=_merge_checks(
                self.sql_injection_checks, other.sql_injection_checks
            ),
            pii_checks=_merge_checks(self.pii_checks, other.pii_checks),
            hardcoded_cred_checks=_merge_checks(
                self.hardcoded_cred_checks, other.hardcoded_cred_checks
            ),
            verbose_error_checks=_merge_checks(
                self.verbose_error_checks, other.verbose_error_checks
            ),
            unrestricted_tool_checks=_merge_checks(
                self.unrestricted_tool_checks, other.unrestricted_tool_checks
            ),
            input_validation=(
                other.input_validation
                if other.input_validation.tool_definition_pattern
                != InputValidationCheck().tool_definition_pattern
                else self.input_validation
            ),
            skip_directories=_merge_unique(self.skip_directories, other.skip_directories),
        )


# ── Private helpers ──────────────────────────────────────────────────


def _merge_checks(
    base: list[CheckDefinition],
    overlay: list[CheckDefinition],
) -> list[CheckDefinition]:
    """Merge check definitions by check_id."""
    return _merge_by_key(base, overlay, key=lambda c: c.check_id)


def _merge_by_key(
    base: list[Any],
    overlay: list[Any],
    *,
    key: Any,
) -> list[Any]:
    """Merge two lists: overlay items replace base items with the same key."""
    index: dict[str, Any] = {key(item): item for item in base}
    for item in overlay:
        index[key(item)] = item
    return list(index.values())


def _merge_unique(base: list[str], overlay: list[str]) -> list[str]:
    """Deduplicated union preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in [*base, *overlay]:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
