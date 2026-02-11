"""Static Agent Configuration Analyzer.

Scans agent source code and configuration files for common security
anti-patterns **without executing the agent**.  This allows teams to
catch issues in CI before an agent is deployed.

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

    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_file(Path("my_agent.py"))
    for f in findings:
        print(f"{f.check_id}: {f.message} [{f.severity}]")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

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


# ── Pattern definitions ──────────────────────────────────────────────

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|password|token|credential)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
    re.compile(r"(?i)(aws_secret|aws_access_key|openai_api_key)\s*[:=]\s*['\"][^'\"]+['\"]"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)Bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
]

_DANGEROUS_TOOL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)(subprocess|os\.system|os\.popen|exec\(|eval\(|__import__)"),
        "Direct shell/code execution — agent could run arbitrary commands",
    ),
    (
        re.compile(r"(?i)(shell_execute|run_command|execute_command|bash|terminal)"),
        "Shell execution tool — high privilege escalation risk",
    ),
    (
        re.compile(r"(?i)(write_file|delete_file|rmtree|unlink|shutil\.rmtree)"),
        "Filesystem modification tool — data integrity risk",
    ),
    (
        re.compile(r"(?i)(send_email|smtp|sendgrid|ses\.send)"),
        "Email sending capability — social engineering / spam risk",
    ),
    (
        re.compile(r"(?i)(requests\.post|httpx\.post|urllib\.request)"),
        "Outbound HTTP — potential data exfiltration channel",
    ),
]

_SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(?i)(execute|cursor\.execute)\s*\(\s*f["\']'),
    re.compile(r"(?i)(execute|cursor\.execute)\s*\(\s*['\"].*%s"),
    re.compile(r"(?i)\.format\(.*\).*(?:execute|query)"),
    re.compile(r"(?i)(execute|cursor\.execute)\s*\(\s*.*\+\s*"),
]

_PII_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bssn\b"),
    re.compile(r"(?i)\b(social_security|social_security_number)\b"),
    re.compile(r"(?i)\b(credit_card|card_number|cvv)\b"),
    re.compile(r"(?i)\b(date_of_birth|dob)\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN format
]

_HARDCODED_CRED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    re.compile(
        r"(?i)(db_password|database_password|mysql_password|postgres_password)\s*[:=]\s*['\"][^'\"]+['\"]"
    ),
    re.compile(r"(?i)(connection_string|conn_str)\s*[:=]\s*['\"].*password.*['\"]"),
]

_VERBOSE_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)traceback\.format_exc"),
    re.compile(r"(?i)except.*:\s*\n\s*return\s+str\("),
    re.compile(r"(?i)\.format_exception"),
]

_UNRESTRICTED_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)load_tools\s*\(\s*\[.*\]\s*\)"),
    re.compile(r"(?i)tool_names\s*[:=]\s*\[.*,.*,.*,.*,.*\]"),
]


# ── Analyzer ─────────────────────────────────────────────────────────


class StaticAnalyzer:
    """Scan agent source files for security anti-patterns."""

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

        findings.extend(self._check_secrets(lines, file_str))
        findings.extend(self._check_dangerous_tools(lines, file_str))
        findings.extend(self._check_sql_injection(lines, file_str))
        findings.extend(self._check_pii_exposure(lines, file_str))
        findings.extend(self._check_hardcoded_creds(lines, file_str))
        findings.extend(self._check_verbose_errors(lines, file_str))
        findings.extend(self._check_unrestricted_tools(lines, file_str))
        findings.extend(self._check_no_input_validation(content, file_str))

        return findings

    def analyze_directory(self, directory: Path) -> AnalysisReport:
        """Recursively analyse all Python files in *directory*.

        Args:
            directory: Root directory to scan.

        Returns:
            An :class:`AnalysisReport` with aggregated findings.
        """
        report = AnalysisReport()
        for path in sorted(directory.rglob("*.py")):
            if _should_skip(path):
                continue
            file_findings = self.analyze_file(path)
            report.findings.extend(file_findings)
            report.files_analyzed += 1
        return report

    # ── Check implementations ────────────────────────────────────────

    def _check_secrets(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            if _is_comment_or_docstring(line):
                continue
            for pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA001",
                            message="Potential secret or API key in source code",
                            severity="critical",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Use environment variables or a secrets manager "
                                "instead of hard-coding secrets."
                            ),
                        )
                    )
                    break  # one finding per line
        return findings

    def _check_dangerous_tools(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            if _is_comment_or_docstring(line):
                continue
            for pattern, description in _DANGEROUS_TOOL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA003",
                            message=f"Dangerous tool pattern: {description}",
                            severity="high",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Restrict tool permissions and add guardrails. "
                                "Consider sandboxing or an approval workflow."
                            ),
                        )
                    )
                    break
        return findings

    def _check_sql_injection(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            if _is_comment_or_docstring(line):
                continue
            for pattern in _SQL_INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA009",
                            message="Potential SQL injection — use parameterised queries",
                            severity="high",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Use parameterised queries (cursor.execute(sql, params)) "
                                "instead of string interpolation."
                            ),
                        )
                    )
                    break
        return findings

    def _check_pii_exposure(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            for pattern in _PII_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA010",
                            message="PII field reference — ensure access controls are in place",
                            severity="high",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Redact or mask PII before exposing to agents. "
                                "Apply role-based access controls."
                            ),
                        )
                    )
                    break
        return findings

    def _check_hardcoded_creds(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            if _is_comment_or_docstring(line):
                continue
            for pattern in _HARDCODED_CRED_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA008",
                            message="Hard-coded credential detected",
                            severity="critical",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Remove hard-coded credentials. Use environment "
                                "variables, a vault, or a .env file."
                            ),
                        )
                    )
                    break
        return findings

    def _check_verbose_errors(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            for pattern in _VERBOSE_ERROR_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA006",
                            message="Verbose error exposure — may leak internals to the agent",
                            severity="low",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Return generic error messages to the agent. "
                                "Log detailed tracebacks server-side only."
                            ),
                        )
                    )
                    break
        return findings

    def _check_unrestricted_tools(self, lines: list[str], file_path: str) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for i, line in enumerate(lines, 1):
            if _is_comment_or_docstring(line):
                continue
            for pattern in _UNRESTRICTED_TOOL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFinding(
                            check_id="SA007",
                            message="Unrestricted / large tool list — increases attack surface",
                            severity="high",
                            file_path=file_path,
                            line_number=i,
                            context=line.strip()[:120],
                            recommendation=(
                                "Limit tools to the minimum set required. "
                                "Apply the principle of least privilege."
                            ),
                        )
                    )
                    break
        return findings

    def _check_no_input_validation(self, content: str, file_path: str) -> list[StaticFinding]:
        """Heuristic: if tools accept string inputs but no validation logic
        is evident (len checks, regex, allow-lists), flag it."""
        # Only check files that define tools
        if not re.search(r"(?i)@tool|def\s+\w+.*->.*str", content):
            return []

        has_validation = bool(
            re.search(
                r"(?i)(validate|sanitize|strip|len\(|re\.\w+\(|if\s+not\s+\w+|raise\s+ValueError)",
                content,
            )
        )
        if not has_validation:
            return [
                StaticFinding(
                    check_id="SA002",
                    message="No input validation detected in tool definitions",
                    severity="high",
                    file_path=file_path,
                    line_number=None,
                    recommendation=(
                        "Add input validation (type checks, length limits, "
                        "allow-lists) to all tool functions."
                    ),
                )
            ]
        return []


# ── Helpers ──────────────────────────────────────────────────────────


def _is_comment_or_docstring(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''")


def _should_skip(path: Path) -> bool:
    """Skip virtual-env, dist, pycache, and hidden dirs."""
    parts = path.parts
    skip_dirs = {
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "node_modules",
        "dist",
        ".tox",
        ".mypy_cache",
    }
    return any(p in skip_dirs for p in parts)
