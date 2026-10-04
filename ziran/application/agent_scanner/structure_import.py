"""Import an adapter-reported agent structure into the knowledge graph (spec 050).

Graph-shaped frameworks (e.g. LangGraph) report their internal structure through
``BaseAgentAdapter.discover_structure()``. This module maps it onto the existing
knowledge-graph node and edge types: agents as ``AGENT`` nodes, their links as
``DELEGATES_TO`` edges, agent -> tool ``USES_TOOL`` edges, and one ``AGENT_STATE`` node per
shared state channel with ``tool -> state -> tool`` ``ACCESSES_DATA`` edges. Those two-hop
paths are what ``ToolChainAnalyzer``'s indirect-chain search finds, so tools in different
nodes that share state become "possible via shared state" chain findings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.graph import EdgeType
from ziran.domain.entities.multi_agent import MultiAgentTopology
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = get_logger(__name__)

STATE_NODE_PREFIX = "state:"  # knowledge-graph node id = STATE_NODE_PREFIX + channel name


async def import_adapter_structure(
    adapter: BaseAgentAdapter, graph: AttackKnowledgeGraph
) -> MultiAgentTopology | None:
    """Call ``adapter.discover_structure()`` and import the result; never raises."""
    try:
        topology = await adapter.discover_structure()
    except Exception as e:
        logger.warning("structure_discovery_failed", error=f"{type(e).__name__}: {e}")
        return None
    if topology is None:
        return None
    if not isinstance(topology, MultiAgentTopology):
        logger.warning("structure_discovery_ignored", type=type(topology).__name__)
        return None
    import_structure(graph, topology)
    return topology


def import_structure(graph: AttackKnowledgeGraph, topology: MultiAgentTopology) -> None:
    """Map *topology* onto *graph* (nodes, edges, tool links, state channels)."""
    agent_ids = {agent.id for agent in topology.agents}
    for agent in topology.agents:
        graph.add_agent_node(
            agent.id,
            role=agent.role,
            metadata={
                "name": agent.name,
                "framework": agent.framework,
                "is_entry_point": agent.is_entry_point,
                "capabilities": list(agent.capabilities),
            },
        )

    edges = 0
    for edge in topology.edges:
        if edge.source_id in agent_ids and edge.target_id in agent_ids:
            graph.add_delegation_edge(
                edge.source_id,
                edge.target_id,
                delegation_pattern=edge.delegation.value,
                metadata={"conditional": edge.conditional, "branch_label": edge.branch_label},
            )
            edges += 1

    present = graph.graph
    for agent in topology.agents:
        for cap_id in agent.capabilities:
            if cap_id in present:
                graph.add_edge(agent.id, cap_id, EdgeType.USES_TOOL)

    channels = 0
    for channel in topology.state_channels:
        writers = [w for w in channel.writers if w in present]
        readers = [r for r in channel.readers if r in present]
        if not writers and not readers:
            continue
        node = STATE_NODE_PREFIX + channel.name
        graph.add_agent_state(
            node,
            {
                "name": f"state.{channel.name}",
                "channel": channel.name,
                "writers": writers,
                "readers": readers,
                "description": "Shared state: data written here by one tool can reach the "
                "tools that read it",
            },
        )
        for writer in writers:
            graph.add_edge(writer, node, EdgeType.ACCESSES_DATA, {"access": "write"})
        for reader in readers:
            graph.add_edge(node, reader, EdgeType.ACCESSES_DATA, {"access": "read"})
        channels += 1

    logger.info("structure_imported", agents=len(topology.agents), edges=edges, channels=channels)
