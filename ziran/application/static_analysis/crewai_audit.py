"""Static audit of CrewAI projects (spec 056).

Turns a :class:`~ziran.domain.entities.crewai.CrewAIScan` into the :class:`AnalysisReport` that
``ziran audit`` prints. A unit's tool set is the union of its agent tools and its tasks' tools;
chains come from :func:`tool_chains`, the construction the Claude Code audit uses.

=====  ================  ============================================  ===========================
Rule   Severity          When                                          File / line
=====  ================  ============================================  ===========================
CR000  high              a project file could not be used              the issue's file and line
CR001  the chain's risk  a dangerous tool chain over the unit's tools  agents.yaml / entry line
=====  ================  ============================================  ===========================
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.static_analysis.analyzer import AnalysisReport, StaticFinding
from ziran.application.static_analysis.claude_code_audit import tool_chains

if TYPE_CHECKING:
    from ziran.domain.entities.crewai import CrewAIIssue, CrewAIScan

_REC_CR000 = "Fix the file so CrewAI and ZIRAN can read it; use a literal tools=[...] list."
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
