"""Static audit of Claude Code subagent definitions (spec 038).

Turns a :class:`~ziran.domain.entities.claude_code.ClaudeCodeScan` into the same
:class:`AnalysisReport` that ``ziran audit`` produces for Python code. Rules
(``T`` is the agent's ``tools`` line, 1 when the key is absent):

=====  ========  =========================================================  ======
Rule   Severity  When                                                       Line
=====  ========  =========================================================  ======
CC000  high      the file could not be parsed (one per scan issue)          issue
CC002  low       a skill bundles a script ZIRAN does not analyse (125)      none
SA001  critical  a secret pattern matches the prompt, description or tools  match
SA003  high      a declared tool is dangerous                               T
SA004  medium    a declared tool is a wildcard grant                        T
SA007  high      no ``tools`` key, or ``*`` alone: every tool is inherited  T
CC001  chain     a dangerous tool chain over the agent's declared tools     T
LT001  critical  the agent's tools cover the lethal trifecta (spec 088)     T
=====  ========  =========================================================  ======

An Agent Skill (spec 125) runs the same rules over its ``allowed-tools`` pre-approvals: no key
grants nothing, so it gets no SA007 and no chain. Its bundled Python files run through the
:class:`StaticAnalyzer`; every skill row carries ATLAS AML.T0110 in ``atlas``.

Never serialise a scan or agent wholesale (``model_dump``): the system prompt and
MCP config may hold secrets. Findings carry only explicit fields.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.chain_analyzer import CHAIN_RULE_ID, ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.knowledge_graph.trifecta import RULE_ID as LT001
from ziran.application.knowledge_graph.trifecta import VULNERABILITY_TYPE as TRIFECTA
from ziran.application.static_analysis.analyzer import (
    AnalysisReport,
    StaticAnalyzer,
    StaticFinding,
    _run_check,
)
from ziran.application.static_analysis.config import StaticAnalysisConfig
from ziran.domain.entities.attack import AtlasTechnique
from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent,
    ClaudeCodeScan,
    ClaudeCodeSkill,
    claude_code_tool_capability,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.domain.entities.capability import DangerousChain

_REC_CC000 = "Fix the agent file so Claude Code and ZIRAN can parse it."
_REC_SA003 = "Remove the tool or scope it with a permission rule, e.g. Bash(npm test:*)."
_REC_SA004 = "Replace the wildcard with the specific tools the agent needs."
_REC_SA007 = "Add a 'tools' list with only the tools the agent needs."
_REC_CC001 = "Remove one tool of the chain from the agent's 'tools' list, or split the agent."
_REC_CC002 = "Review the script by hand: ZIRAN analyses only Python files."
_SKILL_ATLAS = (AtlasTechnique.AI_AGENT_TOOL_POISONING.value,)
_REC_LT001 = (
    "Remove or restrict one leg: drop the egress tool, scope the private data tool, "
    "or keep untrusted content out of this agent."
)


def declared_tools(agent: ClaudeCodeAgent) -> list[str] | None:
    """The agent's declared tool set; None when it inherits every tool (spec 099).

    The file has no ``tools`` key, or the key holds ``*`` alone: inherited. The key is there
    with no tool (``tools:``, ``tools: []``): an empty declared set, which the entity reads
    as None, so the key's line in ``key_lines`` tells the two apart. A skill without
    ``allowed-tools`` pre-approves nothing: an empty set (spec 125).
    """
    if agent.tools is None:
        known = "tools" in agent.key_lines or isinstance(agent, ClaudeCodeSkill)
        return [] if known else None
    return None if agent.tools == ["*"] else agent.tools


def agent_chains(
    agent: ClaudeCodeAgent,
    *,
    typed: bool = False,
    role_overrides: Mapping[str, Iterable[str]] | None = None,
    trifecta_roles: Mapping[str, Iterable[str]] | None = None,
) -> list[DangerousChain]:
    """Dangerous chains over the agent's declared tool set. No execution.

    An inherited tool set gives no chain (spec 099, change 2): it depends on the parent
    session and its MCP servers, which a static reader cannot know. SA007 reports it.

    ``typed`` adds the typed chains of spec 066; ``role_overrides`` (typed only) are roles a
    caller knows, such as the capability job's (spec 067). ``trifecta_roles`` gives a tool's
    lethal trifecta legs in place of the name rules (spec 088).
    """
    tools = declared_tools(agent)
    if not tools:
        return []
    graph = AttackKnowledgeGraph()
    graph.trifecta_roles = {t: frozenset(legs) for t, legs in (trifecta_roles or {}).items()}
    for tool in tools:
        graph.add_capability(tool, claude_code_tool_capability(tool))
    graph.add_co_resident_tools(tools)
    # Cycle enumeration is exponential on a complete graph (12 tools never finish).
    analyzer = ToolChainAnalyzer(graph, typed=typed, role_overrides=role_overrides)
    return analyzer.analyze(include_cycles=False)


def _is_wildcard(tool: str) -> bool:
    if tool.endswith("(*)"):
        return True
    return tool.startswith("mcp__") and (tool.count("__") < 2 or "*" in tool)


def _audit_agent(
    agent: ClaudeCodeAgent,
    config: StaticAnalysisConfig,
    typed: bool = False,
    trifecta_roles: Mapping[str, Iterable[str]] | None = None,
) -> list[StaticFinding]:
    t_line = agent.line_of("tools")
    label = "Skill" if isinstance(agent, ClaudeCodeSkill) else "Agent"

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
            f"{label} '{agent.name}' is granted dangerous tool '{t}'",
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
            f"{label} '{agent.name}' is granted wildcard tool '{t}'",
            _REC_SA004,
            (t,),
        )
        for t in declared
        if _is_wildcard(t)
    ]
    if declared_tools(agent) is None:
        how = "has no 'tools' key" if agent.tools is None else "declares tools '*'"
        what = "pre-approves" if isinstance(agent, ClaudeCodeSkill) else "inherits"
        findings.append(
            finding(
                "SA007",
                "high",
                f"{label} '{agent.name}' {how} and {what} every tool",
                _REC_SA007,
            )
        )
    chains = agent_chains(agent, typed=typed, trifecta_roles=trifecta_roles)
    findings += [
        finding(
            CHAIN_RULE_ID,
            c.risk_level,
            f"{label} '{agent.name}': {c.vulnerability_type} via {' -> '.join(c.tools)}",
            _REC_CC001,
            tuple(c.tools),
        )
        for c in chains
        if c.vulnerability_type != TRIFECTA
    ]
    findings += [
        finding(
            LT001,
            c.risk_level,
            f"{label} '{agent.name}': lethal_trifecta: private data from "
            f"{', '.join(c.evidence['private_data'])}; untrusted content from "
            f"{', '.join(c.evidence['untrusted_content'])}; egress via "
            f"{', '.join(c.evidence['egress'])}",
            _REC_LT001,
            tuple(c.tools),
        )
        for c in chains
        if c.vulnerability_type == TRIFECTA
    ]
    return findings


def audit_claude_code(
    scan: ClaudeCodeScan,
    config: StaticAnalysisConfig | None = None,
    *,
    typed: bool = False,
    trifecta_roles: Mapping[str, Iterable[str]] | None = None,
) -> AnalysisReport:
    """Static findings for every agent in *scan*; files_analyzed = scan.files_analyzed.

    ``typed`` adds typed chains (spec 066) to CC001; off by default. ``trifecta_roles`` are
    the LT001 leg overrides (spec 088).
    """
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
        findings += _audit_agent(agent, config, typed, trifecta_roles)
    analyzed, python = 0, StaticAnalyzer(config)
    for skill in scan.skills:
        rows = _audit_agent(skill, config, typed, trifecta_roles)
        for file in skill.bundled:
            if file.kind == "python":
                rows += python.analyze_file(Path(file.path))
                analyzed += 1
            elif file.kind == "script":
                rows.append(
                    StaticFinding(
                        check_id="CC002",
                        message=f"Skill '{skill.name}' bundles a script that is not analysed",
                        severity="low",
                        file_path=file.path,
                        recommendation=_REC_CC002,
                    )
                )
        findings += [dataclasses.replace(f, agent=skill.name, atlas=_SKILL_ATLAS) for f in rows]
    return AnalysisReport(files_analyzed=scan.files_analyzed + analyzed, findings=findings)
