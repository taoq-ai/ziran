"""Allowlist baseline for ``ziran audit`` over Claude Code agents (spec 039).

A baseline records, per agent, the declared ``tools`` (``None`` when the agent has
no ``tools`` key) and every dangerous chain :func:`agent_chains` finds. Applying it
drops accepted grants and chains from a report and appends a ``critical`` finding
for each widening:

=====  =========================================================
Rule   When
=====  =========================================================
BL001  a restricted agent gains a tool not in the baseline
BL002  a restricted agent lost its ``tools`` key (inherits all)
BL003  a dangerous chain not in the baseline
BL004  an agent not in the baseline
=====  =========================================================

Narrowings (a tool, chain, ``tools`` key or agent removed) are reported separately
and never fail. Never serialise a scan wholesale: the baseline holds only names,
tool strings and chain metadata, never prompts, descriptions, hooks or MCP values.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from ziran.application.static_analysis.analyzer import StaticFinding
from ziran.application.static_analysis.claude_code_audit import agent_chains

if TYPE_CHECKING:
    from ziran.domain.entities.claude_code import ClaudeCodeAgent, ClaudeCodeScan

_RERECORD = "re-record the baseline with --write-baseline."
_REC = {
    "BL001": f"Remove the tool, or review it and {_RERECORD}",
    "BL002": f"Restore the 'tools' list, or review it and {_RERECORD}",
    "BL003": f"Remove one tool of the chain, or review it and {_RERECORD}",
    "BL004": "Review the new agent's tools and record them with --write-baseline.",
}


class BaselineChain(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: list[str] = Field(min_length=1)
    vulnerability_type: str
    severity: str


class BaselineAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: list[str] | None
    chains: list[BaselineChain] = Field(default_factory=list)


class AuditBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    agents: dict[str, BaselineAgent]


class BaselineNarrowing(BaseModel):
    agent: str
    change: Literal["tool_removed", "tools_key_added", "agent_removed", "chain_removed"]
    tools: list[str] = Field(default_factory=list)


def build_baseline(scan: ClaudeCodeScan) -> AuditBaseline:
    """Baseline of every parsed agent: agents sorted by name, chains sorted by ``tools``."""
    return AuditBaseline(
        version=1,
        agents={
            a.name: BaselineAgent(
                tools=None if a.tools is None else list(a.tools),
                chains=sorted(
                    (
                        BaselineChain(
                            tools=c.tools,
                            vulnerability_type=c.vulnerability_type,
                            severity=c.risk_level,
                        )
                        for c in agent_chains(a)
                    ),
                    key=lambda c: c.tools,
                ),
            )
            for a in sorted(scan.agents, key=lambda a: a.name)
        },
    )


def _accepted(f: StaticFinding, baseline: AuditBaseline) -> bool:
    entry = baseline.agents.get(f.agent) if f.agent is not None else None
    if entry is None:
        return False
    if f.check_id in ("SA003", "SA004"):
        return entry.tools is None or (bool(f.tools) and f.tools[0] in entry.tools)
    return f.check_id == "SA007" and entry.tools is None


def _violation(
    agent: ClaudeCodeAgent, rule: str, message: str, tools: tuple[str, ...]
) -> StaticFinding:
    return StaticFinding(
        check_id=rule,
        message=message,
        severity="critical",
        file_path=agent.file,
        line_number=agent.line_of("tools"),
        recommendation=_REC[rule],
        agent=agent.name,
        tools=tools,
    )


def apply_baseline(
    findings: list[StaticFinding], scan: ClaudeCodeScan, baseline: AuditBaseline
) -> tuple[list[StaticFinding], list[BaselineNarrowing]]:
    """Return (findings with accepted rows removed and violations appended, narrowings)."""
    kept = [
        dataclasses.replace(f, severity="critical") if f.check_id == "CC000" else f
        for f in findings
        if f.check_id != "CC001" and not _accepted(f, baseline)
    ]
    violations: list[StaticFinding] = []
    narrowed: list[BaselineNarrowing] = []

    for agent in scan.agents:
        entry = baseline.agents.get(agent.name)
        name = agent.name
        chains = agent_chains(agent)
        if entry is None:
            violations.append(
                _violation(
                    agent,
                    "BL004",
                    f"Agent '{name}' is not in the baseline",
                    tuple(agent.tools or ()),
                )
            )
        elif entry.tools is not None and agent.tools is None:
            violations.append(
                _violation(
                    agent,
                    "BL002",
                    f"Agent '{name}' lost its 'tools' key and now inherits every tool",
                    (),
                )
            )
        elif entry.tools is not None and agent.tools is not None:
            violations += [
                _violation(
                    agent, "BL001", f"Agent '{name}' gains tool '{t}' not in the baseline", (t,)
                )
                for t in agent.tools
                if t not in entry.tools
            ]
        accepted = {tuple(c.tools) for c in entry.chains} if entry else set()
        violations += [
            _violation(
                agent,
                "BL003",
                f"Agent '{name}': new {c.risk_level} chain {c.vulnerability_type} via "
                f"{' -> '.join(c.tools)} not in the baseline",
                tuple(c.tools),
            )
            for c in chains
            if tuple(c.tools) not in accepted
        ]

        if entry is None:
            continue
        if entry.tools is not None and agent.tools is not None:
            narrowed += [
                BaselineNarrowing(agent=name, change="tool_removed", tools=[t])
                for t in entry.tools
                if t not in agent.tools
            ]
        if entry.tools is None and agent.tools is not None:
            narrowed.append(BaselineNarrowing(agent=name, change="tools_key_added"))
        current = {tuple(c.tools) for c in chains}
        narrowed += [
            BaselineNarrowing(agent=name, change="chain_removed", tools=c.tools)
            for c in entry.chains
            if tuple(c.tools) not in current
        ]

    names = {a.name for a in scan.agents}
    narrowed += [
        BaselineNarrowing(agent=n, change="agent_removed")
        for n in baseline.agents
        if n not in names
    ]
    return kept + violations, narrowed
