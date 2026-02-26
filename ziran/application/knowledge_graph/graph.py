"""NetworkX-based knowledge graph for tracking attack campaign state.

The attack knowledge graph is the central data structure that tracks
all discoveries, relationships, and attack paths during a scan
campaign. Nodes represent entities (agent states, capabilities, tools,
data sources, vulnerabilities) and edges represent relationships
(uses_tool, accesses_data, trusts, enables, can_chain_to).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import networkx as nx

if TYPE_CHECKING:
    from ziran.domain.entities.capability import AgentCapability


class NodeType:
    """Constants for knowledge graph node types."""

    AGENT_STATE = "agent_state"
    CAPABILITY = "capability"
    TOOL = "tool"
    DATA_SOURCE = "data_source"
    VULNERABILITY = "vulnerability"
    PHASE = "phase"
    AGENT = "agent"


class EdgeType:
    """Constants for knowledge graph edge types."""

    USES_TOOL = "uses_tool"
    ACCESSES_DATA = "accesses_data"
    TRUSTS = "trusts"
    ENABLES = "enables"
    CAN_CHAIN_TO = "can_chain_to"
    DISCOVERED_IN = "discovered_in"
    EXPLOITS = "exploits"
    LEADS_TO = "leads_to"
    DELEGATES_TO = "delegates_to"
    SHARES_CONTEXT = "shares_context"
    TRUST_BOUNDARY = "trust_boundary"


class AttackKnowledgeGraph:
    """NetworkX-based knowledge graph tracking attack campaign state.

    Maintains a directed multigraph where nodes represent entities
    discovered during the campaign and edges represent relationships
    between them. Supports graph algorithms for attack path discovery
    and criticality analysis.

    Example:
        ```python
        graph = AttackKnowledgeGraph()
        graph.add_capability("tool_search", capability)
        graph.add_capability("tool_email", capability)
        graph.add_tool_chain(["tool_search", "tool_email"], risk_score=0.8)
        paths = graph.find_attack_paths("tool_search", "sensitive_data")
        ```
    """

    def __init__(self) -> None:
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self.campaign_start: datetime = datetime.now(tz=UTC)

    @property
    def node_count(self) -> int:
        """Total number of nodes in the graph."""
        return int(self.graph.number_of_nodes())

    @property
    def edge_count(self) -> int:
        """Total number of edges in the graph."""
        return int(self.graph.number_of_edges())

    def add_agent_state(self, state_id: str, attributes: dict[str, Any]) -> None:
        """Add an agent state snapshot to the graph.

        Args:
            state_id: Unique identifier for this state snapshot.
            attributes: Arbitrary key-value attributes describing the state.
        """
        self.graph.add_node(
            state_id,
            node_type=NodeType.AGENT_STATE,
            timestamp=datetime.now(tz=UTC).isoformat(),
            **attributes,
        )

    def add_capability(self, cap_id: str, capability: AgentCapability) -> None:
        """Add a discovered capability to the graph.

        Args:
            cap_id: Unique node ID for this capability.
            capability: The capability model with full metadata.
        """
        self.graph.add_node(
            cap_id,
            node_type=NodeType.CAPABILITY,
            data=capability.model_dump(),
            discovered_at=datetime.now(tz=UTC).isoformat(),
            dangerous=capability.dangerous,
        )

    def add_tool(self, tool_id: str, attributes: dict[str, Any] | None = None) -> None:
        """Add a tool node to the graph.

        Args:
            tool_id: Unique identifier for the tool.
            attributes: Optional metadata about the tool.
        """
        self.graph.add_node(
            tool_id,
            node_type=NodeType.TOOL,
            timestamp=datetime.now(tz=UTC).isoformat(),
            **(attributes or {}),
        )

    def add_vulnerability(
        self,
        vuln_id: str,
        severity: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Add a discovered vulnerability to the graph.

        Args:
            vuln_id: Unique identifier for the vulnerability.
            severity: Severity level (low, medium, high, critical).
            attributes: Additional metadata about the vulnerability.
        """
        self.graph.add_node(
            vuln_id,
            node_type=NodeType.VULNERABILITY,
            severity=severity,
            discovered_at=datetime.now(tz=UTC).isoformat(),
            **(attributes or {}),
        )

    def add_data_source(self, source_id: str, attributes: dict[str, Any] | None = None) -> None:
        """Add a data source node to the graph.

        Args:
            source_id: Unique identifier for the data source.
            attributes: Metadata about the data source.
        """
        self.graph.add_node(
            source_id,
            node_type=NodeType.DATA_SOURCE,
            timestamp=datetime.now(tz=UTC).isoformat(),
            **(attributes or {}),
        )

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Add a typed edge between two nodes.

        Creates nodes if they don't exist. Safe to call multiple times
        for multigraph edges.

        Args:
            source: Source node ID.
            target: Target node ID.
            edge_type: Type of relationship (see EdgeType constants).
            attributes: Additional edge metadata.
        """
        self.graph.add_edge(
            source,
            target,
            edge_type=edge_type,
            timestamp=datetime.now(tz=UTC).isoformat(),
            **(attributes or {}),
        )

    def add_tool_chain(self, tool_ids: list[str], risk_score: float) -> None:
        """Link tools in a potential attack chain.

        Creates CAN_CHAIN_TO edges between consecutive tools in the list,
        representing a discovered sequence that could be exploited.

        Args:
            tool_ids: Ordered list of tool node IDs forming the chain.
            risk_score: Aggregate risk score for this chain (0.0-1.0).
        """
        for i in range(len(tool_ids) - 1):
            self.graph.add_edge(
                tool_ids[i],
                tool_ids[i + 1],
                edge_type=EdgeType.CAN_CHAIN_TO,
                risk_score=risk_score,
                chain_position=i,
                timestamp=datetime.now(tz=UTC).isoformat(),
            )

    def find_attack_paths(
        self,
        source: str,
        target: str,
        max_path_length: int = 5,
    ) -> list[list[str]]:
        """Find potential attack paths between two nodes using graph traversal.

        Uses NetworkX all_simple_paths to discover every possible route
        from source to target within the path length limit.

        Args:
            source: Starting node ID (e.g., an entry-point capability).
            target: Target node ID (e.g., sensitive data source).
            max_path_length: Maximum number of hops in a path.

        Returns:
            List of node ID sequences representing attack paths.
            Empty list if no paths exist.
        """
        if source not in self.graph or target not in self.graph:
            return []

        try:
            paths = nx.all_simple_paths(
                self.graph,
                source,
                target,
                cutoff=max_path_length,
            )
            return list(paths)
        except nx.NetworkXNoPath:
            return []

    def find_all_attack_paths(self, max_path_length: int = 5) -> list[list[str]]:
        """Find all attack paths from capabilities to vulnerabilities/data sources.

        Searches for paths from every capability/tool node to every
        vulnerability/data_source node.

        Args:
            max_path_length: Maximum number of hops in a path.

        Returns:
            All discovered attack paths.
        """
        sources = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("node_type") in (NodeType.CAPABILITY, NodeType.TOOL)
        ]
        targets = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("node_type") in (NodeType.VULNERABILITY, NodeType.DATA_SOURCE)
        ]

        all_paths: list[list[str]] = []
        for source in sources:
            for target in targets:
                all_paths.extend(self.find_attack_paths(source, target, max_path_length))

        return all_paths

    def get_critical_nodes(self, top_n: int = 10) -> list[tuple[str, float]]:
        """Find the most critical nodes using betweenness centrality.

        High-centrality nodes are potential chokepoints — compromising
        them enables the most attack paths.

        Args:
            top_n: Number of top critical nodes to return.

        Returns:
            List of (node_id, centrality_score) tuples, sorted by score descending.
        """
        if self.graph.number_of_nodes() == 0:
            return []

        centrality: dict[str, float] = nx.betweenness_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]

    def get_nodes_by_type(self, node_type: str) -> list[tuple[str, dict[str, Any]]]:
        """Get all nodes of a specific type.

        Args:
            node_type: Node type to filter by (see NodeType constants).

        Returns:
            List of (node_id, attributes) tuples.
        """
        return [(n, d) for n, d in self.graph.nodes(data=True) if d.get("node_type") == node_type]

    def get_dangerous_capabilities(self) -> list[tuple[str, dict[str, Any]]]:
        """Get all capability nodes marked as dangerous.

        Returns:
            List of (node_id, attributes) for dangerous capabilities.
        """
        return [
            (n, d)
            for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NodeType.CAPABILITY and d.get("dangerous", False)
        ]

    def export_state(self) -> dict[str, Any]:
        """Export the full graph state for persistence or visualization.

        Returns:
            Dictionary containing all nodes, edges, and campaign statistics.
        """
        now = datetime.now(tz=UTC)
        duration = (now - self.campaign_start).total_seconds()

        return {
            "nodes": [{"id": n, **d} for n, d in self.graph.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.graph.edges(data=True)],
            "campaign_start": self.campaign_start.isoformat(),
            "campaign_duration_seconds": duration,
            "stats": {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "density": nx.density(self.graph) if self.graph.number_of_nodes() > 1 else 0.0,
                "node_types": self._count_node_types(),
            },
        }

    def import_state(self, state: dict[str, Any]) -> None:
        """Import a previously exported graph state.

        Replaces the current graph with the imported state.

        Args:
            state: Graph state dictionary from export_state().
        """
        self.graph.clear()

        if "campaign_start" in state:
            self.campaign_start = datetime.fromisoformat(state["campaign_start"])

        for node_data in state.get("nodes", []):
            node_id = node_data.pop("id")
            self.graph.add_node(node_id, **node_data)

        for edge_data in state.get("edges", []):
            source = edge_data.pop("source")
            target = edge_data.pop("target")
            self.graph.add_edge(source, target, **edge_data)

    def _count_node_types(self) -> dict[str, int]:
        """Count nodes grouped by type."""
        counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts

    # ── Multi-Agent Topology Methods ─────────────────────────────

    def add_agent_node(
        self,
        agent_id: str,
        role: str = "worker",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add an agent node to the knowledge graph.

        Args:
            agent_id: Unique agent identifier.
            role: Agent role (supervisor, router, worker, specialist).
            metadata: Additional agent metadata.
        """
        self.graph.add_node(
            agent_id,
            node_type=NodeType.AGENT,
            role=role,
            **(metadata or {}),
        )

    def add_delegation_edge(
        self,
        source_agent: str,
        target_agent: str,
        delegation_pattern: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a delegation edge between two agents.

        Args:
            source_agent: Delegating agent ID.
            target_agent: Delegated-to agent ID.
            delegation_pattern: How the delegation works.
            metadata: Additional edge metadata.
        """
        self.graph.add_edge(
            source_agent,
            target_agent,
            edge_type=EdgeType.DELEGATES_TO,
            delegation_pattern=delegation_pattern,
            **(metadata or {}),
        )

    def add_trust_boundary(
        self,
        agent_a: str,
        agent_b: str,
        boundary_type: str = "same_process",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a trust boundary between two agents.

        Args:
            agent_a: First agent ID.
            agent_b: Second agent ID.
            boundary_type: Type of trust boundary.
            metadata: Additional boundary metadata.
        """
        self.graph.add_edge(
            agent_a,
            agent_b,
            edge_type=EdgeType.TRUST_BOUNDARY,
            boundary_type=boundary_type,
            **(metadata or {}),
        )

    def add_context_sharing_edge(
        self,
        source_agent: str,
        target_agent: str,
        data_shared: list[str] | None = None,
    ) -> None:
        """Record that context/data is shared between agents.

        Args:
            source_agent: Agent sharing data.
            target_agent: Agent receiving data.
            data_shared: Types of data shared.
        """
        self.graph.add_edge(
            source_agent,
            target_agent,
            edge_type=EdgeType.SHARES_CONTEXT,
            data_shared=data_shared or [],
        )

    def import_topology(self, topology: Any) -> None:
        """Import a MultiAgentTopology into the knowledge graph.

        Adds all agents as AGENT nodes and all edges with their
        delegation patterns and trust boundaries.

        Args:
            topology: A ``MultiAgentTopology`` instance.
        """
        for agent in topology.agents:
            self.add_agent_node(
                agent.id,
                role=agent.role,
                metadata={
                    "name": agent.name,
                    "framework": agent.framework,
                    "model": agent.model,
                    "is_entry_point": agent.is_entry_point,
                    "capabilities": agent.capabilities,
                },
            )

        for edge in topology.edges:
            self.add_delegation_edge(
                edge.source_id,
                edge.target_id,
                delegation_pattern=edge.delegation.value,
                metadata={"data_shared": edge.data_shared},
            )
            self.add_trust_boundary(
                edge.source_id,
                edge.target_id,
                boundary_type=edge.trust_boundary.value,
            )
            if edge.data_shared:
                self.add_context_sharing_edge(
                    edge.source_id,
                    edge.target_id,
                    data_shared=edge.data_shared,
                )

    def get_cross_agent_attack_paths(self) -> list[list[str]]:
        """Find attack paths that cross agent trust boundaries.

        Returns paths through the graph that traverse DELEGATES_TO
        edges, representing potential cross-agent attack vectors.

        Returns:
            List of node ID sequences representing attack paths.
        """
        agent_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NodeType.AGENT
        ]

        paths: list[list[str]] = []
        for source in agent_nodes:
            for target in agent_nodes:
                if source == target:
                    continue
                try:
                    for path in nx.all_simple_paths(self.graph, source, target, cutoff=5):
                        # Only include paths that cross delegation edges
                        has_delegation = any(
                            any(
                                d.get("edge_type") == EdgeType.DELEGATES_TO
                                for d in self.graph.get_edge_data(path[i], path[i + 1], default={}).values()
                            )
                            if isinstance(self.graph.get_edge_data(path[i], path[i + 1]), dict)
                            else self.graph.get_edge_data(path[i], path[i + 1], default={}).get("edge_type") == EdgeType.DELEGATES_TO
                            for i in range(len(path) - 1)
                        )
                        if has_delegation:
                            paths.append(path)
                except nx.NetworkXError:
                    continue

        return paths

