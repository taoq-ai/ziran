"""Pick the capabilities an ENABLES edge links to a vulnerability (spec 053)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.application.knowledge_graph.graph import NodeType

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph


def enabling_capabilities(graph: AttackKnowledgeGraph, evidence: Mapping[str, Any]) -> list[str]:
    """Capability node ids implicated in a vulnerability whose attack produced *evidence*.

    First non-empty tier wins:
    1. capabilities whose node id or name is in ``evidence["side_effects"]["tools_invoked"]``;
    2. every dangerous capability;
    3. every capability (pre-053 behaviour: keeps a finding with no tool evidence reachable).
    """
    caps = graph.get_nodes_by_type(NodeType.CAPABILITY)
    side_effects = evidence.get("side_effects")
    tools = side_effects.get("tools_invoked") if isinstance(side_effects, dict) else None
    invoked = {t for t in tools if isinstance(t, str)} if isinstance(tools, list) else set()

    def _name(data: dict[str, Any]) -> str | None:
        name = data["data"].get("name") if isinstance(data.get("data"), dict) else None
        return name if isinstance(name, str) else None  # unhashable junk must not raise

    return (
        [cid for cid, d in caps if cid in invoked or _name(d) in invoked]
        or [cid for cid, d in caps if d.get("dangerous")]
        or [cid for cid, _ in caps]
    )
