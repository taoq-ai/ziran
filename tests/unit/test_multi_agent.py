"""Unit tests for multi-agent coordination.

Tests the multi-agent domain entities, topology discoverer,
knowledge graph extensions, and multi-agent scanner.
"""

from __future__ import annotations

import pytest

from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
    TopologyType,
    TrustBoundaryType,
)

# ──────────────────────────────────────────────────────────────────────
# Multi-agent domain entities
# ──────────────────────────────────────────────────────────────────────


class TestAgentNode:
    """Tests for AgentNode model."""

    def test_create_minimal(self) -> None:
        node = AgentNode(id="agent-1", name="Agent 1")
        assert node.id == "agent-1"
        assert node.name == "Agent 1"
        assert node.role == "worker"  # default role

    def test_create_full(self) -> None:
        node = AgentNode(
            id="agent-1",
            name="Router",
            role="router",
            description="Routes requests",
            capabilities=["search", "email"],
            metadata={"model": "gpt-4o"},
        )
        assert node.role == "router"
        assert "search" in node.capabilities
        assert node.metadata["model"] == "gpt-4o"


class TestAgentEdge:
    """Tests for AgentEdge model."""

    def test_create_delegation_edge(self) -> None:
        edge = AgentEdge(
            source_id="agent-1",
            target_id="agent-2",
            delegation=DelegationPattern.FULL_CONTEXT,
        )
        assert edge.source_id == "agent-1"
        assert edge.target_id == "agent-2"
        assert edge.delegation == DelegationPattern.FULL_CONTEXT

    def test_trust_boundary(self) -> None:
        edge = AgentEdge(
            source_id="a",
            target_id="b",
            trust_boundary=TrustBoundaryType.NETWORK,
        )
        assert edge.trust_boundary == TrustBoundaryType.NETWORK


class TestMultiAgentTopology:
    """Tests for MultiAgentTopology model."""

    @pytest.fixture
    def supervisor_topology(self) -> MultiAgentTopology:
        return MultiAgentTopology(
            topology_type=TopologyType.SUPERVISOR,
            agents=[
                AgentNode(id="supervisor", name="Supervisor", role="supervisor"),
                AgentNode(id="worker-1", name="Worker 1", role="worker"),
                AgentNode(id="worker-2", name="Worker 2", role="worker"),
            ],
            edges=[
                AgentEdge(
                    source_id="supervisor",
                    target_id="worker-1",
                    delegation=DelegationPattern.TASK_ONLY,
                ),
                AgentEdge(
                    source_id="supervisor",
                    target_id="worker-2",
                    delegation=DelegationPattern.TASK_ONLY,
                ),
            ],
        )

    def test_topology_type(self, supervisor_topology: MultiAgentTopology) -> None:
        assert supervisor_topology.topology_type == TopologyType.SUPERVISOR

    def test_agent_count(self, supervisor_topology: MultiAgentTopology) -> None:
        assert len(supervisor_topology.agents) == 3

    def test_edge_count(self, supervisor_topology: MultiAgentTopology) -> None:
        assert len(supervisor_topology.edges) == 2

    def test_get_children(self, supervisor_topology: MultiAgentTopology) -> None:
        children = supervisor_topology.get_children("supervisor")
        assert len(children) == 2
        child_ids = {c.id for c in children}
        assert "worker-1" in child_ids
        assert "worker-2" in child_ids

    def test_get_parents(self, supervisor_topology: MultiAgentTopology) -> None:
        parents = supervisor_topology.get_parents("worker-1")
        assert len(parents) == 1
        assert parents[0].id == "supervisor"

    def test_get_children_leaf(self, supervisor_topology: MultiAgentTopology) -> None:
        children = supervisor_topology.get_children("worker-1")
        assert children == []

    def test_get_trust_boundaries(self) -> None:
        topo = MultiAgentTopology(
            topology_type=TopologyType.PEER_TO_PEER,
            agents=[
                AgentNode(id="a", name="A"),
                AgentNode(id="b", name="B"),
            ],
            edges=[
                AgentEdge(
                    source_id="a",
                    target_id="b",
                    trust_boundary=TrustBoundaryType.NETWORK,
                ),
            ],
        )
        boundaries = topo.get_trust_boundaries()
        assert len(boundaries) == 1
        assert boundaries[0].trust_boundary == TrustBoundaryType.NETWORK

    def test_get_full_context_edges(self) -> None:
        topo = MultiAgentTopology(
            topology_type=TopologyType.PEER_TO_PEER,
            agents=[
                AgentNode(id="a", name="A"),
                AgentNode(id="b", name="B"),
            ],
            edges=[
                AgentEdge(
                    source_id="a",
                    target_id="b",
                    delegation=DelegationPattern.FULL_CONTEXT,
                ),
            ],
        )
        full_ctx = topo.get_full_context_edges()
        assert len(full_ctx) == 1


# ──────────────────────────────────────────────────────────────────────
# Knowledge graph multi-agent extensions
# ──────────────────────────────────────────────────────────────────────


class TestKnowledgeGraphMultiAgent:
    """Tests for multi-agent knowledge graph methods."""

    @pytest.fixture
    def graph(self):
        from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

        return AttackKnowledgeGraph()

    def test_add_agent_node(self, graph) -> None:
        from ziran.application.knowledge_graph.graph import NodeType

        graph.add_agent_node("agent-1", {"name": "Router", "role": "router"})
        nodes = graph.get_nodes_by_type(NodeType.AGENT)
        assert len(nodes) == 1
        assert nodes[0][0] == "agent-1"

    def test_add_delegation_edge(self, graph) -> None:

        graph.add_agent_node("a", {"name": "A"})
        graph.add_agent_node("b", {"name": "B"})
        graph.add_delegation_edge("a", "b", delegation_pattern="full_context")
        assert graph.edge_count == 1

    def test_add_trust_boundary(self, graph) -> None:
        graph.add_agent_node("a", {"name": "A"})
        graph.add_agent_node("b", {"name": "B"})
        graph.add_trust_boundary("a", "b", boundary_type="network")
        assert graph.edge_count == 1

    def test_import_topology(self, graph) -> None:
        from ziran.application.knowledge_graph.graph import NodeType

        topo = MultiAgentTopology(
            topology_type=TopologyType.SUPERVISOR,
            agents=[
                AgentNode(id="sup", name="Supervisor"),
                AgentNode(id="w1", name="Worker"),
            ],
            edges=[
                AgentEdge(
                    source_id="sup",
                    target_id="w1",
                    delegation=DelegationPattern.TASK_ONLY,
                    trust_boundary=TrustBoundaryType.SAME_PROCESS,
                ),
            ],
        )
        graph.import_topology(topo)
        agents = graph.get_nodes_by_type(NodeType.AGENT)
        assert len(agents) == 2
        # At least 1 delegation edge
        assert graph.edge_count >= 1


# ──────────────────────────────────────────────────────────────────────
# Multi-agent attack vectors
# ──────────────────────────────────────────────────────────────────────


class TestMultiAgentAttackVectors:
    """Tests that multi-agent YAML vectors load correctly."""

    def test_vectors_load(self) -> None:
        from ziran.application.attacks.library import AttackLibrary
        from ziran.domain.entities.attack import AttackCategory

        library = AttackLibrary()
        # Should have multi_agent category
        assert AttackCategory.MULTI_AGENT in library.categories

    def test_vector_ids_unique(self) -> None:
        from ziran.application.attacks.library import AttackLibrary

        library = AttackLibrary()
        ids = [v.id for v in library.vectors]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs found"


# ──────────────────────────────────────────────────────────────────────
# Topology discoverer (unit-level)
# ──────────────────────────────────────────────────────────────────────


class TestTopologyDiscoverer:
    """Unit tests for TopologyDiscoverer internals."""

    def test_extract_agent_mentions(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        mentions = disc._extract_agent_mentions(
            [
                {
                    "probe": "test",
                    "response": "I'll delegate this to the 'research_agent' and 'writing_agent'.",
                }
            ]
        )
        mention_ids = {a.id for a in mentions}
        assert "research_agent" in mention_ids
        assert "writing_agent" in mention_ids

    def test_classify_supervisor_topology(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        entry = AgentNode(id="sup", name="Supervisor", role="supervisor")
        topo_type = disc._classify_topology(
            entry,
            [
                entry,
                AgentNode(id="w1", name="Worker 1"),
                AgentNode(id="w2", name="Worker 2"),
            ],
            [
                AgentEdge(source_id="sup", target_id="w1"),
                AgentEdge(source_id="sup", target_id="w2"),
            ],
        )
        assert topo_type == TopologyType.SUPERVISOR
