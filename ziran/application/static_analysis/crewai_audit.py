"""Static audit of CrewAI projects (spec 056).

Turns a :class:`~ziran.domain.entities.crewai.CrewAIScan` into the :class:`AnalysisReport` that
``ziran audit`` prints. A unit's tool set is the union of its agent tools and its tasks' tools;
chains come from :func:`tool_chains`, the construction the Claude Code audit uses.

=====  ================  ============================================  ===========================
Rule   Severity          When                                          File / line
=====  ================  ============================================  ===========================
CR000  high              a project file could not be used, or a unit   the issue's file and line
                         names more than ``MAX_UNIT_TOOLS`` tools
CR001  the chain's risk  a dangerous tool chain over the unit's tools  agents.yaml / entry line
=====  ================  ============================================  ===========================
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ziran.application.static_analysis.analyzer import AnalysisReport, StaticFinding
from ziran.application.static_analysis.claude_code_audit import tool_chains
from ziran.domain.entities.crewai import CrewAIIssue

if TYPE_CHECKING:
    from ziran.domain.entities.crewai import CrewAIScan

# Chain construction is quadratic in tools (about 6 s at 100, 58 s at 300), and a 1 MiB file can
# name thousands. A unit above the bound gets CR000 instead of chains, never a truncated set.
MAX_UNIT_TOOLS: Final = 64

_REC_CR000 = (
    "Fix the file so CrewAI and ZIRAN can read it (use a literal tools=[...] list), or split an"
    " agent with too many tools."
)
_REC_CR001 = "Remove one tool of the chain from the agent or its tasks, or split the agent."


def _cr000(issue: CrewAIIssue, agent: str | None) -> StaticFinding:
    return StaticFinding(
        check_id="CR000",
        message=issue.message,
        severity="high",
        file_path=issue.file,
        line_number=issue.line,
        recommendation=_REC_CR000,
        agent=agent,
    )


def audit_crewai(scan: CrewAIScan) -> AnalysisReport:
    """CR000 per scan issue, then per unit its CR000 errors and CR001 chains."""
    findings = [_cr000(issue, None) for issue in scan.issues]
    for unit in scan.agents:
        findings += [_cr000(error, unit.name) for error in unit.errors]
        if len(unit.tools) > MAX_UNIT_TOOLS:
            message = f"agent has more than {MAX_UNIT_TOOLS} tools; chains not built"
            issue = CrewAIIssue(file=unit.file, line=unit.line, message=message)
            findings.append(_cr000(issue, unit.name))
            continue
        findings += [
            StaticFinding(
                check_id="CR001",
                message=f"Agent '{unit.name}': {c.vulnerability_type} via {' -> '.join(c.tools)}",
                severity=c.risk_level,  # type: ignore[arg-type]
                file_path=unit.file,
                line_number=unit.line,
                recommendation=_REC_CR001,
                agent=unit.name,
                tools=tuple(c.tools),
            )
            for c in tool_chains(unit.tools)
        ]
    return AnalysisReport(files_analyzed=scan.files_analyzed, findings=findings)
