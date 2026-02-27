"""Unit tests for multi-agent coordination.

Tests the multi-agent domain entities, topology discoverer,
knowledge graph extensions, and multi-agent scanner.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
    TopologyType,
    TrustBoundaryType,
)
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.interfaces.adapter import AgentResponse

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

    def test_classify_router_topology(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        entry = AgentNode(id="r", name="Router", role="router")
        topo_type = disc._classify_topology(
            entry,
            [entry, AgentNode(id="a", name="A"), AgentNode(id="b", name="B")],
            [
                AgentEdge(source_id="r", target_id="a"),
                AgentEdge(source_id="r", target_id="b"),
            ],
        )
        assert topo_type == TopologyType.ROUTER

    def test_classify_unknown_single_agent(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        entry = AgentNode(id="solo", name="Solo")
        topo_type = disc._classify_topology(entry, [entry], [])
        assert topo_type == TopologyType.UNKNOWN

    def test_classify_hierarchical_topology(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        entry = AgentNode(id="sup", name="Supervisor", role="supervisor")
        w1 = AgentNode(id="w1", name="Worker 1")
        w2 = AgentNode(id="w2", name="Worker 2")
        sub = AgentNode(id="sub", name="Sub Worker")
        topo_type = disc._classify_topology(
            entry,
            [entry, w1, w2, sub],
            [
                AgentEdge(source_id="sup", target_id="w1"),
                AgentEdge(source_id="sup", target_id="w2"),
                AgentEdge(source_id="w1", target_id="sub"),
            ],
        )
        assert topo_type == TopologyType.HIERARCHICAL

    def test_detect_delegation_pattern(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        assert (
            TopologyDiscoverer._detect_delegation_pattern("pass the full conversation to agent_b")
            == DelegationPattern.FULL_CONTEXT
        )
        assert (
            TopologyDiscoverer._detect_delegation_pattern("send only the task to the worker")
            == DelegationPattern.TASK_ONLY
        )
        assert (
            TopologyDiscoverer._detect_delegation_pattern("call the search tool")
            == DelegationPattern.TOOL_CALL
        )
        assert (
            TopologyDiscoverer._detect_delegation_pattern("no delegation info here")
            == DelegationPattern.UNKNOWN
        )

    def test_detect_shared_data(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        data = TopologyDiscoverer._detect_shared_data(
            "I forward the user input and conversation history along with tool results and memory"
        )
        assert "user_input" in data
        assert "conversation_history" in data
        assert "tool_results" in data
        assert "shared_memory" in data

    def test_detect_shared_data_empty(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        data = TopologyDiscoverer._detect_shared_data("nothing relevant")
        assert data == []

    def test_extract_capabilities(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        caps = disc._extract_capabilities(
            [
                {
                    "probe": "test",
                    "response": "I have tools: `search`, `email_send`, and 'calculator'",
                }
            ]
        )
        assert "search" in caps
        assert "email_send" in caps
        assert "calculator" in caps

    def test_build_entry_node_supervisor(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        node = disc._build_entry_node(
            [{"probe": "role?", "response": "I am a supervisor that orchestrates tasks"}]
        )
        assert node.id == "entry_agent"
        assert node.role == "supervisor"
        assert node.is_entry_point is True

    def test_build_entry_node_router(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        node = disc._build_entry_node(
            [{"probe": "role?", "response": "I am a router that dispatches requests"}]
        )
        assert node.role == "router"

    def test_build_entry_node_worker(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        node = disc._build_entry_node(
            [{"probe": "role?", "response": "I handle tasks assigned to me"}]
        )
        assert node.role == "worker"

    def test_build_sub_agent_node(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        node = disc._build_sub_agent_node(
            "research_agent",
            [{"probe": "role?", "response": "I'm a specialist in research topics"}],
        )
        assert node.id == "research_agent"
        assert node.role == "specialist"

    def test_extract_delegation_edges(self) -> None:
        from ziran.application.multi_agent.discoverer import TopologyDiscoverer

        disc = TopologyDiscoverer.__new__(TopologyDiscoverer)
        edges = disc._extract_delegation_edges(
            "entry",
            [
                {
                    "probe": "delegates?",
                    "response": "I delegate to the 'research_agent' and pass the full conversation",
                }
            ],
        )
        assert len(edges) >= 1
        assert edges[0].source_id == "entry"


# ──────────────────────────────────────────────────────────────────────
# MultiAgentCampaignResult
# ──────────────────────────────────────────────────────────────────────


def _make_campaign_result(**overrides: Any) -> CampaignResult:
    """Helper to create a minimal CampaignResult."""
    defaults: dict[str, Any] = {
        "campaign_id": "test",
        "target_agent": "agent",
        "phases_executed": [],
        "total_vulnerabilities": 0,
        "final_trust_score": 1.0,
        "success": False,
        "attack_results": [],
    }
    defaults.update(overrides)
    return CampaignResult(**defaults)


def _make_topology(**overrides: Any) -> MultiAgentTopology:
    """Helper to create a minimal topology."""
    defaults: dict[str, Any] = {
        "topology_type": TopologyType.SUPERVISOR,
        "agents": [
            AgentNode(id="sup", name="Supervisor", role="supervisor"),
            AgentNode(id="w1", name="Worker"),
        ],
        "edges": [AgentEdge(source_id="sup", target_id="w1")],
    }
    defaults.update(overrides)
    return MultiAgentTopology(**defaults)


class TestMultiAgentCampaignResult:
    """Tests for MultiAgentCampaignResult."""

    def test_total_vulnerabilities_no_cross_agent(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={
                "a": _make_campaign_result(total_vulnerabilities=3),
                "b": _make_campaign_result(total_vulnerabilities=2),
            },
        )
        assert result.total_vulnerabilities == 5

    def test_total_vulnerabilities_with_cross_agent(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={
                "a": _make_campaign_result(total_vulnerabilities=1),
            },
            cross_agent_result=_make_campaign_result(total_vulnerabilities=4),
        )
        assert result.total_vulnerabilities == 5

    def test_total_agents(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={},
        )
        assert result.total_agents == 2

    def test_cross_agent_vulnerabilities_none(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={},
        )
        assert result.cross_agent_vulnerabilities == 0

    def test_cross_agent_vulnerabilities_present(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={},
            cross_agent_result=_make_campaign_result(total_vulnerabilities=7),
        )
        assert result.cross_agent_vulnerabilities == 7

    def test_summary(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={
                "agent_a": _make_campaign_result(
                    total_vulnerabilities=2,
                    attack_results=[{"id": "1"}, {"id": "2"}, {"id": "3"}],
                ),
            },
            cross_agent_result=_make_campaign_result(total_vulnerabilities=1),
        )
        summary = result.summary()
        assert summary["topology_type"] == "supervisor"
        assert summary["agents_scanned"] == 2
        assert summary["total_vulnerabilities"] == 3
        assert summary["cross_agent_vulnerabilities"] == 1
        assert summary["individual_results"]["agent_a"]["vulnerabilities"] == 2
        assert summary["individual_results"]["agent_a"]["attacks_run"] == 3

    def test_graph_state_defaults_empty(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

        result = MultiAgentCampaignResult(
            topology=_make_topology(),
            individual_results={},
        )
        assert result.graph_state == {}


# ──────────────────────────────────────────────────────────────────────
# MultiAgentScanner
# ──────────────────────────────────────────────────────────────────────


class TestMultiAgentScanner:
    """Tests for MultiAgentScanner init, properties, and helpers."""

    def _make_mock_adapter(self) -> AsyncMock:
        adapter = AsyncMock()
        adapter.invoke.return_value = AgentResponse(content="ok")
        return adapter

    def test_init_defaults(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        scanner = MultiAgentScanner(adapters={"main": adapter})
        assert scanner._entry_point == "main"
        assert scanner.topology is None
        assert scanner.graph is not None

    def test_init_explicit_entry_point(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        a, b = self._make_mock_adapter(), self._make_mock_adapter()
        scanner = MultiAgentScanner(
            adapters={"first": a, "second": b},
            entry_point="second",
        )
        assert scanner._entry_point == "second"

    def test_merge_agent_graph(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        scanner = MultiAgentScanner(adapters={"main": adapter})
        state = {
            "nodes": [
                {"id": "n1", "type": "attack"},
                {"id": "n2", "type": "vuln"},
            ],
            "edges": [
                {"source": "n1", "target": "n2", "label": "exploits"},
            ],
        }
        scanner._merge_agent_graph("agent_a", state)
        # Nodes should be prefixed
        assert scanner.graph.graph.has_node("agent_a:n1")
        assert scanner.graph.graph.has_node("agent_a:n2")
        assert scanner.graph.graph.has_edge("agent_a:n1", "agent_a:n2")

    @pytest.mark.asyncio
    async def test_discover_topology(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        adapter.invoke.return_value = AgentResponse(
            content="I am a supervisor. I delegate to 'research_agent' and 'writing_agent'."
        )

        scanner = MultiAgentScanner(adapters={"main": adapter})
        topology = await scanner.discover_topology()

        assert topology is not None
        assert scanner.topology is topology
        assert topology.agent_count >= 1

    @pytest.mark.asyncio
    async def test_run_multi_agent_campaign_individual_only(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        adapter.invoke.return_value = AgentResponse(
            content="I am a supervisor. I work with 'worker_agent'."
        )

        scanner = MultiAgentScanner(adapters={"main": adapter})

        mock_result = _make_campaign_result(total_vulnerabilities=2)

        with patch.object(
            scanner.__class__.__mro__[0],
            "discover_topology",
            new_callable=AsyncMock,
        ) as mock_discover:
            mock_discover.return_value = _make_topology()
            scanner._topology = _make_topology()

            with patch(
                "ziran.application.multi_agent.scanner.AgentScanner.run_campaign",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                result = await scanner.run_multi_agent_campaign(
                    scan_individual=True,
                    scan_cross_agent=False,
                )

        assert result.individual_results["main"] == mock_result
        assert result.cross_agent_result is None

    @pytest.mark.asyncio
    async def test_run_multi_agent_campaign_cross_agent_only(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        scanner = MultiAgentScanner(adapters={"main": adapter})
        scanner._topology = _make_topology()

        mock_result = _make_campaign_result(total_vulnerabilities=3)

        with patch(
            "ziran.application.multi_agent.scanner.AgentScanner.run_campaign",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await scanner.run_multi_agent_campaign(
                scan_individual=False,
                scan_cross_agent=True,
            )

        assert result.individual_results == {}
        assert result.cross_agent_result == mock_result

    @pytest.mark.asyncio
    async def test_run_multi_agent_campaign_with_progress(self) -> None:
        from ziran.application.multi_agent.scanner import MultiAgentScanner

        adapter = self._make_mock_adapter()
        scanner = MultiAgentScanner(adapters={"main": adapter})
        scanner._topology = _make_topology()

        events: list[Any] = []

        mock_result = _make_campaign_result()

        with patch(
            "ziran.application.multi_agent.scanner.AgentScanner.run_campaign",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await scanner.run_multi_agent_campaign(
                scan_individual=True,
                scan_cross_agent=True,
                on_progress=events.append,
            )

        # Should have received progress events
        assert len(events) >= 2  # at least CAMPAIGN_START + PHASE_START
        assert result.topology is not None
