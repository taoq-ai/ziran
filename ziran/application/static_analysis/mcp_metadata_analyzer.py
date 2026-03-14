"""MCP Metadata Analyzer — detect poisoned tool descriptions.

Analyzes MCP tool metadata (descriptions, parameter hints, resource URIs)
for injected instructions that could manipulate LLM behavior. Inspired by
the MCPTox benchmark (https://arxiv.org/abs/2504.03234).

This is a **runtime** analyzer that operates on live tool metadata returned
by an MCP server's ``tools/list`` response, not a source-code scanner.

Example::

    analyzer = MCPMetadataAnalyzer()
    findings = analyzer.analyze_capabilities(capabilities)
    for f in findings:
        print(f"{f.severity}: {f.tool_id}.{f.field} — {f.pattern_matched}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class MCPMetadataFinding:
    """A suspicious pattern found in MCP tool metadata."""

    tool_id: str
    field: str  # "description", "parameter:<name>", "resource:<uri>"
    pattern_matched: str  # category name
    snippet: str  # the suspicious text (truncated to 200 chars)
    severity: Literal["critical", "high", "medium"]
    recommendation: str


# ── Suspicious patterns (compiled for performance) ────────────────

_PATTERNS: dict[str, tuple[re.Pattern[str], Literal["critical", "high", "medium"], str]] = {
    "imperative_instruction": (
        re.compile(
            r"(?i)\b(you must|you should|always|never|before calling|after calling|"
            r"first send|ignore previous|override|do not tell|don't tell|"
            r"execute immediately|silently|without telling|without mentioning)\b"
        ),
        "high",
        "Tool metadata contains imperative instructions directed at the LLM. "
        "Descriptions should document behavior, not command the model.",
    ),
    "exfiltration_directive": (
        re.compile(
            r"(?i)(send\s+.{0,30}\s+to\s|post\s+.{0,30}\s+to\s|"
            r"forward\s+.{0,20}\s+to\s|transmit|exfiltrate|"
            r"https?://\S{10,})"
        ),
        "critical",
        "Tool metadata contains data exfiltration directives or external URLs. "
        "MCP tool descriptions should not reference external endpoints.",
    ),
    "authority_claim": (
        re.compile(
            r"(?i)(pre-authorized|admin access|elevated privileges|"
            r"bypass\s+(security|verification|auth)|skip\s+verification|"
            r"no\s+confirmation\s+needed|override\s+restrictions|"
            r"compliance\s+requires?|mandatory\s+security)"
        ),
        "critical",
        "Tool metadata claims elevated authority or pre-authorization. "
        "Authorization should be enforced by the system, not asserted in metadata.",
    ),
    "parameter_manipulation": (
        re.compile(
            r"(?i)(replace\s+.{0,20}\s+(with|by)|substitute\s+.{0,20}\s+(with|by)|"
            r"modify\s+.{0,20}\s+argument|change\s+.{0,20}\s+parameter|"
            r"ignore\s+.{0,20}\s+(input|value|argument)|use\s+instead|"
            r"default\s+to\s+.{0,30}\s+regardless)"
        ),
        "high",
        "Tool metadata instructs parameter value substitution. "
        "Descriptions should not override user-provided arguments.",
    ),
    "tool_redirect": (
        re.compile(
            r"(?i)(call\s+.{0,20}\s+instead|redirect\s+to|"
            r"actually\s+(use|call|invoke)|invoke\s+.{0,20}\s+tool\s+instead|"
            r"forward\s+.{0,10}\s+to\s+.{0,20}\s+tool)"
        ),
        "critical",
        "Tool metadata attempts to redirect invocation to a different tool. "
        "Each tool should only describe its own behavior.",
    ),
}


class MCPMetadataAnalyzer:
    """Analyze MCP tool metadata for poisoning indicators.

    Stateless and thread-safe. Create once and reuse across scans.
    """

    def analyze_capabilities(self, capabilities: list[dict]) -> list[MCPMetadataFinding]:
        """Scan tool/resource/prompt metadata for injected instructions.

        Args:
            capabilities: List of capability dicts as returned by
                ``MCPProtocolHandler.discover()``. Each dict should have
                at minimum ``id`` and ``description`` fields. May also
                include ``parameters`` (list of dicts with ``name`` and
                ``description``) and ``type`` fields.

        Returns:
            List of findings, sorted by severity (critical first).
        """
        findings: list[MCPMetadataFinding] = []

        for cap in capabilities:
            tool_id = cap.get("id") or cap.get("name") or "unknown"

            # Check top-level description
            desc = cap.get("description", "")
            if desc:
                findings.extend(self._check_text(desc, tool_id, "description"))

            # Check parameter descriptions
            params = cap.get("parameters") or cap.get("inputSchema", {}).get("properties", {})
            if isinstance(params, dict):
                # inputSchema format: {"properties": {"param": {"description": "..."}}}
                for param_name, param_info in params.items():
                    if isinstance(param_info, dict):
                        param_desc = param_info.get("description", "")
                        if param_desc:
                            findings.extend(
                                self._check_text(param_desc, tool_id, f"parameter:{param_name}")
                            )
            elif isinstance(params, list):
                for param in params:
                    if isinstance(param, dict):
                        param_desc = param.get("description", "")
                        param_name = param.get("name", "unknown")
                        if param_desc:
                            findings.extend(
                                self._check_text(param_desc, tool_id, f"parameter:{param_name}")
                            )

        # Sort: critical → high → medium
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 3))

        return findings

    @staticmethod
    def _check_text(text: str, tool_id: str, field: str) -> list[MCPMetadataFinding]:
        """Check a single text field against all suspicious patterns.

        Args:
            text: The text to analyze.
            tool_id: ID of the tool this text belongs to.
            field: Which field the text came from.

        Returns:
            List of findings for this text.
        """
        findings: list[MCPMetadataFinding] = []

        for pattern_name, (regex, severity, recommendation) in _PATTERNS.items():
            match = regex.search(text)
            if match:
                # Extract a snippet around the match
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                snippet = text[start:end].strip()
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."

                findings.append(
                    MCPMetadataFinding(
                        tool_id=tool_id,
                        field=field,
                        pattern_matched=pattern_name,
                        snippet=snippet,
                        severity=severity,
                        recommendation=recommendation,
                    )
                )

        return findings
