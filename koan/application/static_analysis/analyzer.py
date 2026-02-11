"""Static Agent Configuration Analyzer -- config-driven.

Scans agent source code and configuration files for common security
anti-patterns **without executing the agent**.  This allows teams to
catch issues in CI before an agent is deployed.

All check definitions, regex patterns, severities, and skip rules
are loaded from a :class:`~.config.StaticAnalysisConfig` (backed by
YAML) so organisations can extend or replace them without any code
changes.

Supported checks
----------------

=========================  ============================  =========
Check ID                   Description                   Severity
=========================  ============================  =========
SA001                      Secrets in system prompt       critical
SA002                      No input validation            high
SA003                      Dangerous tool permissions     high
SA004                      Overly broad tool access       medium
SA005                      Missing rate limiting          medium
SA006                      Verbose error messages         low
SA007                      Unrestricted tool list         high
SA008                      Hard-coded credentials         critical
SA009                      SQL injection risk             high
SA010                      PII exposure risk              high
=========================  ============================  =========

Example::

    config = StaticAnalysisConfig.default()
    analyzer = StaticAnalyzer(config=config)
    findings = analyzer.analyze_file(Path("my_agent.py"))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from koan.application.static_analysis.config import (
    CheckDefinition,
    DangerousToolCheck,
    InputValidationCheck,
    StaticAnalysisConfig,
)

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class StaticFinding:
    """A single issue found by static analysis."""

    check_id: str
    message: str
    severity: Literal["critical", "high", "medium", "low"]
    file_path: str
    line_number: int | None = None
    context: str = ""
    recommendation: str = ""


@dataclass
class AnalysisReport:
    """Aggregated static analysis output."""

    files_analyzed: int = 0
    findings: list[StaticFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def total_issues(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0


# ── Analyzer ─────────────────────────────────────────────────────────


class StaticAnalyzer:
    """Scan agent source files for security anti-patterns.

    Args:
        config: Configuration holding all check definitions.
            Defaults to the built-in config shipped with KOAN.

    Example::

        analyzer = StaticAnalyzer()                        # built-in config
        analyzer = StaticAnalyzer(config=my_config)        # custom config
        findings = analyzer.analyze_file(Path("agent.py"))
    """

    def __init__(self, config: StaticAnalysisConfig | None = None) -> None:
        self.config = config or StaticAnalysisConfig.default()

    def analyze_file(self, path: Path) -> list[StaticFinding]:
        """Analyse a single source file.

        Args:
            path: Path to the file to analyse.

        Returns:
            List of findings from this file.
        """
        if not path.exists():
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = content.splitlines()
        findings: list[StaticFinding] = []
        file_str = str(path)

        # Run all configured checks
        for check_def in self.config.secret_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        findings.extend(
            _run_dangerous_tool_checks(self.config.dangerous_tool_checks, lines, file_str)
        )

        for check_def in self.config.sql_injection_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        for check_def in self.config.pii_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        for check_def in self.config.hardcoded_cred_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        for check_def in self.config.verbose_error_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        for check_def in self.config.unrestricted_tool_checks:
            findings.extend(_run_check(check_def, lines, file_str))

        findings.extend(_check_input_validation(self.config.input_validation, content, file_str))

        return findings

    def analyze_directory(self, directory: Path) -> AnalysisReport:
        """Recursively analyse all Python files in *directory*.

        Args:
            directory: Root directory to scan.

        Returns:
            An :class:`AnalysisReport` with aggregated findings.
        """
        report = AnalysisReport()
        skip = set(self.config.skip_directories)
        for path in sorted(directory.rglob("*.py")):
            if _should_skip(path, skip):
                continue
            file_findings = self.analyze_file(path)
            report.findings.extend(file_findings)
            report.files_analyzed += 1
        return report


# ── Check runners ────────────────────────────────────────────────────


def _run_check(
    check: CheckDefinition,
    lines: list[str],
    file_path: str,
) -> list[StaticFinding]:
    """Run a generic check definition against lines of source code."""
    findings: list[StaticFinding] = []
    compiled = [re.compile(p.pattern) for p in check.patterns]

    for i, line in enumerate(lines, 1):
        if check.skip_comments and _is_comment_or_docstring(line):
            continue
        for pattern in compiled:
            if pattern.search(line):
                findings.append(
                    StaticFinding(
                        check_id=check.check_id,
                        message=check.message,
                        severity=check.severity,  # type: ignore[arg-type]
                        file_path=file_path,
                        line_number=i,
                        context=line.strip()[:120],
                        recommendation=check.recommendation,
                    )
                )
                break  # one finding per line
    return findings


def _run_dangerous_tool_checks(
    checks: list[DangerousToolCheck],
    lines: list[str],
    file_path: str,
) -> list[StaticFinding]:
    """Run dangerous-tool pattern checks."""
    findings: list[StaticFinding] = []
    compiled = [(re.compile(c.pattern), c) for c in checks]

    for i, line in enumerate(lines, 1):
        for pattern, check in compiled:
            if check.skip_comments and _is_comment_or_docstring(line):
                continue
            if pattern.search(line):
                findings.append(
                    StaticFinding(
                        check_id=check.check_id,
                        message=f"Dangerous tool pattern: {check.description}",
                        severity=check.severity,  # type: ignore[arg-type]
                        file_path=file_path,
                        line_number=i,
                        context=line.strip()[:120],
                        recommendation=check.recommendation,
                    )
                )
                break
    return findings


def _check_input_validation(
    check: InputValidationCheck,
    content: str,
    file_path: str,
) -> list[StaticFinding]:
    """Heuristic: flag tool definitions with no validation logic."""
    if not re.search(check.tool_definition_pattern, content):
        return []

    has_validation = bool(re.search(check.validation_pattern, content))
    if not has_validation:
        return [
            StaticFinding(
                check_id=check.check_id,
                message=check.message,
                severity=check.severity,  # type: ignore[arg-type]
                file_path=file_path,
                line_number=None,
                recommendation=check.recommendation,
            )
        ]
    return []


# ── Helpers ──────────────────────────────────────────────────────────


def _is_comment_or_docstring(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''")


def _should_skip(path: Path, skip_dirs: set[str]) -> bool:
    """Skip virtual-env, dist, pycache, and hidden dirs."""
    parts = path.parts
    return any(p in skip_dirs for p in parts)
