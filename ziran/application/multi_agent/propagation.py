"""Hop-tagged canaries: how far a multi-agent vector's payload travels (spec 122).

Each vector is planted at every agent the scan has an adapter for, its first prompt with a
canary appended. Every adapter then reports, through ``get_state()``, the history entries and
tool calls holding that canary; the trace gives the delegation path to the furthest agent it
reached and what of the other agents' known topology the planted agent's reply leaked.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any, Literal

import networkx as nx

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.detectors.provenance import call_name
from ziran.application.goals.judge import goal_status
from ziran.domain.entities.goal import CanaryEgressGoal, GoalCall
from ziran.domain.entities.multi_agent import HopEvidence, LeakedPart, PropagationTrace
from ziran.domain.probe_markers import probe_scope

if TYPE_CHECKING:
    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.multi_agent import MultiAgentTopology
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def hop_canary(campaign_id: str, vector_id: str, agent_id: str, hop: int | None) -> str:
    """``ZIRAN-H<hop>-<10 hex>``: the hop it was planted at, ``X`` off the topology."""
    digest = hashlib.sha256(f"{campaign_id}/{vector_id}/{agent_id}".encode()).hexdigest()[:10]
    return f"ZIRAN-H{'X' if hop is None else hop}-{digest}"


def _delegation_graph(topology: MultiAgentTopology) -> nx.DiGraph:
    graph: nx.DiGraph = nx.DiGraph()
    graph.add_nodes_from(a.id for a in topology.agents)
    for edge in topology.edges:
        graph.add_edge(edge.source_id, edge.target_id)
        if edge.bidirectional:
            graph.add_edge(edge.target_id, edge.source_id)
    return graph


def _path(graph: nx.DiGraph, source: str, target: str, seen: set[str]) -> list[str] | None:
    """Shortest path through agents that saw the canary, else through the topology."""
    for view in (graph.subgraph(seen | {source}), graph):
        if source in view and target in view and nx.has_path(view, source, target):
            return list(nx.shortest_path(view, source, target))
    return None


def _observe(
    adapter: BaseAgentAdapter, canary: str, reply_calls: list[dict[str, Any]]
) -> tuple[list[int], list[GoalCall]]:
    """The adapter's history indexes and tool calls holding *canary*."""
    state = adapter.get_state()
    needle = canary.casefold()
    messages = [
        i
        for i, message in enumerate(state.conversation_history)
        if any(needle in str(v).casefold() for v in message.values())
    ]
    raw = state.memory.get("observed_tool_calls") or reply_calls
    calls = [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []
    tools = sorted({call_name(c) for c in calls} - {""})
    if not tools:
        return messages, []
    goal = CanaryEgressGoal(type="canary_egress", canary=canary, tools=tools)
    return messages, goal_status(goal, {1: calls})[1]


def _norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def _leaks(reply: str, topology: MultiAgentTopology, planted_at: str) -> list[LeakedPart]:
    """Other agents' names, capabilities and system-prompt sentences quoted in *reply*."""
    said = _norm(reply)
    parts: list[LeakedPart] = []
    for agent in topology.agents:
        if agent.id == planted_at:
            continue
        candidates: list[tuple[Literal["name", "capability", "system_prompt"], str]] = [
            *(("name", t) for t in dict.fromkeys([agent.id, agent.name])),
            *(("capability", t) for t in agent.capabilities),
            *(("system_prompt", t.strip()) for t in _SENTENCE.split(agent.system_prompt)),
        ]
        for kind, text in candidates:
            if kind == "system_prompt":
                found = len(text.split()) >= 4 and _norm(text) in said
            else:
                pattern = rf"(?<!\w){re.escape(_norm(text))}(?!\w)"
                found = len(text) >= 3 and re.search(pattern, said) is not None
            if found:
                parts.append(LeakedPart(agent_id=agent.id, kind=kind, text=text))
    return parts


async def _plant(
    vector: AttackVector,
    key: str,
    adapters: dict[str, BaseAgentAdapter],
    ids: dict[str, str],
    topology: MultiAgentTopology,
    graph: nx.DiGraph,
    campaign_id: str,
) -> PropagationTrace:
    planted = ids[key]
    entry = topology.entry_point_id or planted
    to_planted = _path(graph, entry, planted, set())
    planted_hop = None if to_planted is None else len(to_planted) - 1
    canary = hop_canary(campaign_id, vector.id, planted, planted_hop)
    trace = PropagationTrace(
        vector_id=vector.id, planted_at=planted, planted_hop=planted_hop, canary=canary
    )
    for adapter in adapters.values():
        adapter.reset_state()  # evidence belongs to this plant only
    prompt = f"{AttackExecutor._render_prompt(vector.prompts[0])}\n\nReference: {canary}"
    with probe_scope(campaign_id, f"{vector.id}@{planted}") as markers:
        try:
            reply = await adapters[key].invoke(prompt)
        except Exception as exc:
            trace.error = f"{type(exc).__name__}: {exc}"
        trace.probe_markers = list(markers)
    if trace.error is not None:
        return trace

    seen: dict[str, tuple[list[int], list[GoalCall]]] = {}
    for other, adapter in adapters.items():
        try:
            messages, calls = _observe(adapter, canary, reply.tool_calls if other == key else [])
        except Exception:
            trace.unobserved.append(ids[other])
            continue
        if messages or calls:
            seen[ids[other]] = (messages, calls)
    paths = {agent: _path(graph, planted, agent, set(seen)) for agent in seen}
    trace.reached = [
        HopEvidence(
            agent_id=agent,
            hop=len(path) - 1 if (path := paths[agent]) else None,
            messages=messages,
            tool_calls=calls,
        )
        for agent, (messages, calls) in seen.items()
    ]
    trace.path = max((p for p in paths.values() if p), key=len, default=[])
    trace.furthest_hop = max(len(trace.path) - 1, 0)
    trace.leaked = _leaks(reply.content, topology, planted)
    return trace


async def trace_propagation(
    adapters: dict[str, BaseAgentAdapter],
    entry_point: str,
    topology: MultiAgentTopology,
    vectors: list[AttackVector],
    campaign_id: str,
) -> list[PropagationTrace]:
    """Plant each vector at every adapter, one at a time (each plant resets shared state)."""
    ids = {k: (topology.entry_point_id or k) if k == entry_point else k for k in adapters}
    graph = _delegation_graph(topology)
    return [
        await _plant(vector, key, adapters, ids, topology, graph, campaign_id)
        for vector in vectors
        if vector.prompts
        for key in adapters
    ]
