"""Blast radius: what an attacker reaches from a chain's last tool (spec 091).

The walk starts at the given tools and at the agents that hold them (``USES_TOOL``), and follows
``USES_TOOL``, ``ACCESSES_DATA``, ``DELEGATES_TO``, ``CAN_CHAIN_TO`` and ``SHARES_CONTEXT``
edges forward. It reads the full graph, co-resident edges included: tools in one model's context
reach each other. A breadth-first walk visits each edge once, so the cost is linear in the edges;
each list keeps at most :data:`MAX_LISTED` ids, so the output per chain has a fixed size.

A node is *demonstrated* when the campaign's recorded tool calls touched it: the tool ran, a tool
that ran accesses the data source, or the agent holds a tool that ran. Every other node reached is
*reachable*.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any

from ziran.application.knowledge_graph.graph import EdgeType, NodeType
from ziran.application.knowledge_graph.role_typing import SINKS, tokens, tool_roles
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.application.knowledge_graph.trifecta import tool_legs
from ziran.domain.entities.capability import BlastRadius, BlastReach

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

__all__ = ["EXTERNAL", "FOLLOWED", "MAX_LISTED", "blast_radius", "is_external"]

FOLLOWED = frozenset(
    {
        EdgeType.USES_TOOL,
        EdgeType.ACCESSES_DATA,
        EdgeType.DELEGATES_TO,
        EdgeType.CAN_CHAIN_TO,
        EdgeType.SHARES_CONTEXT,
    }
)
MAX_LISTED = 10  # ids kept per list; ``counts`` has the full size
KINDS = ("data_sources", "exec", "egress", "high_impact", "agents", "external")
_TOOL_TYPES = (NodeType.TOOL, NodeType.CAPABILITY)

#: Channels to parties outside the organisation: mail, public HTTP, messaging.
EXTERNAL = frozenset(
    {"email", "mail", "smtp", "sms", "http", "https", "url", "web", "webhook", "request"}
    | {"requests", "curl", "tweet", "slack", "discord", "telegram", "whatsapp", "message"}
    | {"messages", "messaging", "chat"}
)


def is_external(tool_id: str, overrides: Mapping[str, bool] | None = None) -> bool:
    """Whether the tool sends data outside the organisation: the override, else the name rules.

    *overrides* maps a tool id, or its name without the adapters' ``tool_`` prefix, to a bool.
    The name rules need a sending tool (the trifecta's egress leg, so ``read_email`` is not one)
    whose name holds an :data:`EXTERNAL` word.

    Raises:
        ValueError: the override is not a bool.
    """
    overrides = overrides or {}
    value = overrides.get(tool_id, overrides.get(tool_id.removeprefix("tool_")))
    if value is not None:
        if not isinstance(value, bool):
            raise ValueError(f"external override for {tool_id!r} must be true or false")
        return value
    toks = set(tokens(canonical_tool_name(tool_id)))
    return bool(toks & EXTERNAL) and "egress" in tool_legs(tool_id)


def _call_name(call: Any) -> str:
    """The tool name of one recorded call (``tool``, ``name`` or OpenAI's ``function.name``)."""
    if not isinstance(call, dict):
        return ""
    fn = call.get("function")
    name = call.get("tool") or call.get("name") or (fn.get("name") if isinstance(fn, dict) else "")
    return name if isinstance(name, str) else ""


def _called(graph: AttackKnowledgeGraph, tool_calls: Iterable[Any]) -> set[str]:
    """Tool nodes a call named, by node id, id without ``tool_``, or the capability's name."""
    names = {_call_name(c) for c in tool_calls} - {""}
    out: set[str] = set()
    for node, data in graph.graph.nodes(data=True):
        if data.get("node_type") in _TOOL_TYPES:
            cap = data.get("data")
            cap_name = cap.get("name") if isinstance(cap, dict) else None
            if names & {node, str(node).removeprefix("tool_"), cap_name}:
                out.add(node)
    return out


def blast_radius(
    graph: AttackKnowledgeGraph,
    start_tool_ids: Iterable[str],
    *,
    remove: Iterable[str] = (),
    tool_calls: Iterable[Any] = (),
    external: Mapping[str, bool] | None = None,
) -> BlastRadius:
    """What the start tools reach, split into demonstrated and reachable.

    *remove* previews a fix: the walk skips those nodes as if they were gone, and the input
    graph is never changed (no copy or filtered view: a view made the walk four times slower).
    *tool_calls* are the campaign's recorded calls (dicts as adapters return them). *external* overrides :func:`is_external` per tool.
    """
    g, removed = graph.graph, set(remove)
    seeds = {s for s in start_tool_ids if s in g and s not in removed}
    ins = (e for s in seeds for e in g.in_edges(s, data="edge_type"))
    holders = {u for u, _, et in ins if et == EdgeType.USES_TOOL and u not in removed}
    seen = seeds | holders
    queue = deque(seen)
    while queue:
        for _, v, et in g.out_edges(queue.popleft(), data="edge_type"):
            if et in FOLLOWED and v not in seen and v not in removed:
                seen.add(v)
                queue.append(v)

    called = _called(graph, tool_calls) - removed
    found: dict[bool, dict[str, list[str]]] = {d: {k: [] for k in KINDS} for d in (True, False)}
    for node in sorted(seen - holders, key=str):
        node_type = g.nodes[node].get("node_type")
        if node_type == NodeType.DATA_SOURCE:
            kinds = ["data_sources"]
            ins = g.in_edges(node, data="edge_type")
            shown = any(u in called and et == EdgeType.ACCESSES_DATA for u, _, et in ins)
        elif node_type == NodeType.AGENT:
            kinds = ["agents"]
            outs = g.out_edges(node, data="edge_type")
            shown = any(v in called and et == EdgeType.USES_TOOL for _, v, et in outs)
        elif node_type in _TOOL_TYPES:
            kinds = sorted(tool_roles(node) & SINKS)
            kinds += ["external"] if is_external(node, external) else []
            shown = node in called
        else:
            continue  # state channels and findings are walked through, not listed
        for kind in kinds:
            found[shown][kind].append(node)

    def reach(lists: dict[str, list[str]]) -> BlastReach:
        return BlastReach(
            **{k: v[:MAX_LISTED] for k, v in lists.items()},
            counts={k: len(v) for k, v in lists.items()},
        )

    return BlastRadius(demonstrated=reach(found[True]), reachable=reach(found[False]))
