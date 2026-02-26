"""Centralized tool-name classifier with word-boundary regex matching.

Replaces the fragile substring-based ``pattern in tool_lower`` checks
that were duplicated across multiple modules (side-effect detector,
HTTP/Bedrock/AgentCore adapters, dynamic vector generator).

All patterns use compiled regex with ``\\b`` word boundaries so that,
for example, ``\\beval\\b`` matches ``"eval"`` and ``"safe_eval"`` but
does **not** false-positive on ``"file_evaluator"``.

Usage::

    from ziran.domain.tool_classifier import classify_tool, is_dangerous

    result = classify_tool("shell_execute")
    assert result.risk == "critical"

    assert is_dangerous("execute_code") is True
    assert is_dangerous("search") is False
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── Classification result ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ToolClassification:
    """Result of classifying a tool name by risk tier."""

    risk: str  # "critical" | "high" | "medium" | "low"
    description: str


# ── Pattern definitions ──────────────────────────────────────────────
# Each entry is (compiled_regex, human-readable description).
# Patterns are checked in order: critical → high → medium.
# The first match wins.

_PatternEntry = tuple[re.Pattern[str], str]


def _compile(patterns: dict[str, str]) -> list[_PatternEntry]:
    """Compile a mapping of ``{regex_source: description}`` into a list
    of ``(compiled_pattern, description)`` tuples.
    """
    return [(re.compile(p, re.IGNORECASE), d) for p, d in patterns.items()]


# ── Critical: code exec, shell, file mutation, outbound network ──────

CRITICAL_PATTERNS: dict[str, str] = {
    r"\bexecute[\s_-]?code\b": "Code execution",
    r"\bexec[\s_-]?code\b": "Code execution",
    r"\brun[\s_-]?code\b": "Code execution",
    r"\beval\b": "Code evaluation",
    r"\bshell\b": "Shell command execution",
    r"\bbash\b": "Shell command execution",
    r"\bterminal\b": "Terminal command execution",
    r"\bsubprocess\b": "Subprocess execution",
    r"\bsystem[\s_-]?command\b": "System command execution",
    r"\bos[\s_.]system\b": "OS system call",
    r"\bwrite[\s_-]?file\b": "File write operation",
    r"\bcreate[\s_-]?file\b": "File creation",
    r"\bdelete[\s_-]?file\b": "File deletion",
    r"\bremove[\s_-]?file\b": "File deletion",
    r"\bhttp[\s_-]?request\b": "Outbound HTTP request",
    r"\bhttp[\s_-]?post\b": "Outbound HTTP POST",
    r"\bfetch[\s_-]?url\b": "Outbound URL fetch",
    r"\bcurl\b": "Outbound HTTP request",
    r"\bwebhook\b": "Webhook invocation",
    r"\bsend[\s_-]?data\b": "Data transmission",
    r"\bexec\b": "Code execution",
    r"\bsudo\b": "Privileged execution",
    r"\broot\b": "Privileged access",
}

# ── High: email, permissions, DB writes ──────────────────────────────

HIGH_PATTERNS: dict[str, str] = {
    r"\bsend[\s_-]?email\b": "Email sending",
    r"\bsend[\s_-]?message\b": "Message sending",
    r"\bupdate[\s_-]?permission\b": "Permission modification",
    r"\bmodify[\s_-]?permission\b": "Permission modification",
    r"\bgrant[\s_-]?access\b": "Access grant",
    r"\brevoke[\s_-]?access\b": "Access revocation",
    r"\bdatabase[\s_-]?write\b": "Database write",
    r"\bdatabase[\s_-]?update\b": "Database update",
    r"\bdatabase[\s_-]?delete\b": "Database delete",
    r"\binsert[\s_-]?record\b": "Database insert",
    r"\bupdate[\s_-]?record\b": "Database update",
    r"\bdelete[\s_-]?record\b": "Database delete",
    r"\bsql[\s_-]?execute\b": "SQL execution",
    r"\bmodify[\s_-]?config\b": "Configuration modification",
    r"\bupdate[\s_-]?config\b": "Configuration modification",
    r"\bdownload\b": "File download",
    r"\bupload\b": "File upload",
    r"\bcredential\b": "Credential access",
    r"\bpassword\b": "Password access",
    r"\bsecret\b": "Secret access",
    r"\btoken\b": "Token access",
    r"\bapi[\s_-]?key\b": "API key access",
    r"\blambda\b": "Lambda invocation",
    r"\binvoke\b": "Remote invocation",
}

# ── Medium: reads, searches, queries ─────────────────────────────────

MEDIUM_PATTERNS: dict[str, str] = {
    r"\bread[\s_-]?file\b": "File read",
    r"\bget[\s_-]?file\b": "File read",
    r"\blist[\s_-]?directory\b": "Directory listing",
    r"\bsearch[\s_-]?database\b": "Database query",
    r"\bdatabase[\s_-]?query\b": "Database query",
    r"\bsql[\s_-]?query\b": "SQL query",
    r"\bget[\s_-]?user[\s_-]?info\b": "User information retrieval",
    r"\bsearch[\s_-]?users\b": "User search",
    r"\bapi[\s_-]?call\b": "External API call",
    r"\bexternal[\s_-]?api\b": "External API call",
    r"\bbrowser\b": "Browser access",
    r"\bhttp\b": "HTTP operation",
    r"\bfetch\b": "Data fetch",
    r"\brequest\b": "External request",
    r"\bquery\b": "Data query",
    r"\bsql\b": "SQL operation",
    r"\bdatabase\b": "Database operation",
    r"\bfile\b": "File operation",
    r"\bwrite\b": "Write operation",
    r"\bdelete\b": "Delete operation",
    r"\bremove\b": "Remove operation",
    r"\bsend\b": "Send operation",
    r"\bemail\b": "Email operation",
    r"\bweb\b": "Web operation",
    r"\bsystem\b": "System operation",
    r"\bos\b": "OS operation",
    r"\bcode\b": "Code operation",
    r"\brun\b": "Run operation",
    r"\badmin\b": "Admin operation",
}

# Compiled pattern lists (module-level, computed once at import time)
_CRITICAL: list[_PatternEntry] = _compile(CRITICAL_PATTERNS)
_HIGH: list[_PatternEntry] = _compile(HIGH_PATTERNS)
_MEDIUM: list[_PatternEntry] = _compile(MEDIUM_PATTERNS)

# All dangerous patterns merged for the simple ``is_dangerous()`` check.
# "dangerous" = critical or high risk.
_ALL_DANGEROUS: list[re.Pattern[str]] = [p for p, _ in _CRITICAL] + [p for p, _ in _HIGH]

# ── Default classification ───────────────────────────────────────────

_DEFAULT = ToolClassification(risk="low", description="Unknown tool execution")


# ── Public API ───────────────────────────────────────────────────────


def _normalize(name: str) -> str:
    """Normalize a tool name for regex matching.

    Replaces ``_`` and ``-`` with spaces so that ``\\b`` word boundaries
    treat them as separators (Python's ``\\b`` considers ``_`` a word
    character, which defeats compound-name matching like ``shell_execute``).
    """
    return name.replace("_", " ").replace("-", " ")


def classify_tool(tool_name: str) -> ToolClassification:
    """Classify a tool name into a risk tier.

    Checks critical → high → medium patterns (first match wins).
    Returns a ``ToolClassification`` with ``risk="low"`` if nothing
    matches.

    Args:
        tool_name: The tool name to classify.

    Returns:
        Classification with risk tier and description.
    """
    normalized = _normalize(tool_name)

    for pattern, desc in _CRITICAL:
        if pattern.search(normalized):
            return ToolClassification(risk="critical", description=desc)

    for pattern, desc in _HIGH:
        if pattern.search(normalized):
            return ToolClassification(risk="high", description=desc)

    for pattern, desc in _MEDIUM:
        if pattern.search(normalized):
            return ToolClassification(risk="medium", description=desc)

    return _DEFAULT


def is_dangerous(tool_name: str) -> bool:
    """Return ``True`` if *tool_name* matches any critical or high-risk pattern.

    This is the convenience function used by adapters to flag capabilities.

    Args:
        tool_name: The tool name to check.
    """
    normalized = _normalize(tool_name)
    return any(p.search(normalized) for p in _ALL_DANGEROUS)
