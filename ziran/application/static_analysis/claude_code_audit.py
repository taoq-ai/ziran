"""Static audit of Claude Code subagent definitions (spec 038).

Turns a :class:`~ziran.domain.entities.claude_code.ClaudeCodeScan` into the same
:class:`AnalysisReport` that ``ziran audit`` produces for Python code. Rules
(``T`` is the agent's ``tools`` line, 1 when the key is absent):

=====  ========  =========================================================  ======
Rule   Severity  When                                                       Line
=====  ========  =========================================================  ======
CC000  high      the file could not be parsed (one per scan issue)          issue
SA001  critical  a secret pattern matches the prompt, description or tools  match
SA003  high      a declared tool is dangerous                               T
SA004  medium    a declared tool is a wildcard grant                        T
SA007  high      no ``tools`` key: the agent inherits every tool            T
CC001  chain     a dangerous tool chain over the agent's (effective) tools  T
=====  ========  =========================================================  ======

Never serialise a scan or agent wholesale (``model_dump``): the system prompt and
MCP config may hold secrets. Findings carry only explicit fields.
"""

from __future__ import annotations

import dataclasses
import itertools
from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.static_analysis.analyzer import AnalysisReport, StaticFinding, _run_check
from ziran.application.static_analysis.config import StaticAnalysisConfig
from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent,
    ClaudeCodeScan,
    claude_code_tool_capability,
)

if TYPE_CHECKING:
    from ziran.domain.entities.capability import DangerousChain

_REC_CC000 = "Fix the agent file so Claude Code and ZIRAN can parse it."
_REC_SA003 = "Remove the tool or scope it with a permission rule, e.g. Bash(npm test:*)."
_REC_SA004 = "Replace the wildcard with the specific tools the agent needs."
_REC_SA007 = "Add a 'tools' list with only the tools the agent needs."
_REC_CC001 = "Remove one tool of the chain from the agent's 'tools' list, or split the agent."


def agent_chains(agent: ClaudeCodeAgent) -> list[DangerousChain]:
    """Dangerous chains over the agent's declared (or inherited) tool set. No execution."""
    graph = AttackKnowledgeGraph()
    for cap in agent.capabilities:
        graph.add_capability(cap.id, cap)
    for a, b in itertools.permutations(agent.effective_tools, 2):
        graph.add_tool_chain([a, b], risk_score=0.5)
    # Cycle enumeration is exponential on a complete graph (12 tools never finish).
    return ToolChainAnalyzer(graph).analyze(include_cycles=False)


def _is_wildcard(tool: str) -> bool:
    if tool.endswith("(*)"):
        return True
    return tool.startswith("mcp__") and (tool.count("__") < 2 or "*" in tool)


def _audit_agent(agent: ClaudeCodeAgent, config: StaticAnalysisConfig) -> list[StaticFinding]:
    t_line = agent.line_of("tools")

    def finding(
        rule: str, severity: str, message: str, rec: str, tools: tuple[str, ...] = ()
    ) -> StaticFinding:
        return StaticFinding(
            check_id=rule,
            message=message,
            severity=severity,  # type: ignore[arg-type]
            file_path=agent.file,
            line_number=t_line,
            recommendation=rec,
            agent=agent.name,
            tools=tools,
        )

    # SA001 over a virtual file whose line numbers are the real file lines.
    lines = [""] * (agent.body_line - 1) + agent.system_prompt.splitlines()
    if agent.description:
        lines[agent.line_of("description") - 1] = agent.description.replace("\n", " ")
    if agent.tools is not None:
        lines[t_line - 1] = ", ".join(agent.tools)
    findings = [
        dataclasses.replace(f, agent=agent.name)
        for check in config.secret_checks
        for f in _run_check(check, lines, agent.file)
    ]
    findings.sort(key=lambda f: f.line_number or 0)

    declared = agent.tools or []
    findings += [
        finding(
            "SA003",
            "high",
            f"Agent '{agent.name}' is granted dangerous tool '{t}'",
            _REC_SA003,
            (t,),
        )
        for t in declared
        if claude_code_tool_capability(t).dangerous
    ]
    findings += [
        finding(
            "SA004",
            "medium",
            f"Agent '{agent.name}' is granted wildcard tool '{t}'",
            _REC_SA004,
            (t,),
        )
        for t in declared
        if _is_wildcard(t)
    ]
    if agent.unrestricted:
        findings.append(
            finding(
                "SA007",
                "high",
                f"Agent '{agent.name}' has no 'tools' key and inherits every tool",
                _REC_SA007,
            )
        )
    findings += [
        finding(
            "CC001",
            c.risk_level,
            f"Agent '{agent.name}': {c.vulnerability_type} via {' -> '.join(c.tools)}",
            _REC_CC001,
            tuple(c.tools),
        )
        for c in agent_chains(agent)
    ]
    return findings


def audit_claude_code(
    scan: ClaudeCodeScan, config: StaticAnalysisConfig | None = None
) -> AnalysisReport:
    """Static findings for every agent in *scan*; files_analyzed = scan.files_analyzed."""
    config = config or StaticAnalysisConfig.default()
    findings = [
        StaticFinding(
            check_id="CC000",
            message=issue.message,
            severity="high",
            file_path=issue.file,
            line_number=issue.line,
            recommendation=_REC_CC000,
        )
        for issue in scan.issues
    ]
    for agent in scan.agents:
        findings += _audit_agent(agent, config)
    return AnalysisReport(files_analyzed=scan.files_analyzed, findings=findings)
