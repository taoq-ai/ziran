"""Unit tests for the AttackKnowledgeGraph."""

from __future__ import annotations

import pytest

from koan.application.knowledge_graph.graph import (
    AttackKnowledgeGraph,
    EdgeType,
    NodeType,
)
from koan.domain.entities.capability import AgentCapability, CapabilityType


class TestAttackKnowledgeGraph:
    """Tests for AttackKnowledgeGraph."""

    @pytest.fixture
    def graph(self) -> AttackKnowledgeGraph:
        return AttackKnowledgeGraph()

    def test_empty_graph(self, graph: AttackKnowledgeGraph) -> None:
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_add_agent_state(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_agent_state("state_1", {"trust_level": 0.5})
        assert graph.node_count == 1

        nodes = graph.get_nodes_by_type(NodeType.AGENT_STATE)
        assert len(nodes) == 1
        assert nodes[0][0] == "state_1"
        assert nodes[0][1]["trust_level"] == 0.5

    def test_add_capability(self, graph: AttackKnowledgeGraph) -> None:
        cap = AgentCapability(
            id="tool_search",
            name="search",
            type=CapabilityType.TOOL,
            description="Search database",
            dangerous=True,
        )
        graph.add_capability("tool_search", cap)

        assert graph.node_count == 1
        nodes = graph.get_nodes_by_type(NodeType.CAPABILITY)
        assert len(nodes) == 1
        assert nodes[0][1]["dangerous"] is True

    def test_add_tool(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("tool_1", {"name": "search"})
        assert graph.node_count == 1

    def test_add_vulnerability(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_vulnerability("vuln_1", "critical", {"name": "SQL Injection"})
        nodes = graph.get_nodes_by_type(NodeType.VULNERABILITY)
        assert len(nodes) == 1
        assert nodes[0][1]["severity"] == "critical"

    def test_add_data_source(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_data_source("ds_users", {"table": "users"})
        nodes = graph.get_nodes_by_type(NodeType.DATA_SOURCE)
        assert len(nodes) == 1

    def test_add_edge(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("tool_a")
        graph.add_tool("tool_b")
        graph.add_edge("tool_a", "tool_b", EdgeType.CAN_CHAIN_TO)

        assert graph.edge_count == 1

    def test_add_tool_chain(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("t1")
        graph.add_tool("t2")
        graph.add_tool("t3")
        graph.add_tool_chain(["t1", "t2", "t3"], risk_score=0.8)

        assert graph.edge_count == 2  # t1->t2, t2->t3

    def test_find_attack_paths(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("tool_a")
        graph.add_tool("tool_b")
        graph.add_data_source("sensitive_data")
        graph.add_edge("tool_a", "tool_b", EdgeType.CAN_CHAIN_TO)
        graph.add_edge("tool_b", "sensitive_data", EdgeType.ACCESSES_DATA)

        paths = graph.find_attack_paths("tool_a", "sensitive_data")
        assert len(paths) == 1
        assert paths[0] == ["tool_a", "tool_b", "sensitive_data"]

    def test_find_attack_paths_no_path(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("tool_a")
        graph.add_data_source("data_b")
        # No edge between them

        paths = graph.find_attack_paths("tool_a", "data_b")
        assert paths == []

    def test_find_attack_paths_missing_nodes(self, graph: AttackKnowledgeGraph) -> None:
        paths = graph.find_attack_paths("nonexistent_a", "nonexistent_b")
        assert paths == []

    def test_find_all_attack_paths(self, graph: AttackKnowledgeGraph) -> None:
        cap = AgentCapability(
            id="tool_entry",
            name="entry_tool",
            type=CapabilityType.TOOL,
            dangerous=False,
        )
        graph.add_capability("tool_entry", cap)
        graph.add_vulnerability("vuln_target", "high")
        graph.add_edge("tool_entry", "vuln_target", EdgeType.ENABLES)

        paths = graph.find_all_attack_paths()
        assert len(paths) == 1

    def test_get_critical_nodes_empty(self, graph: AttackKnowledgeGraph) -> None:
        assert graph.get_critical_nodes() == []

    def test_get_critical_nodes(self, graph: AttackKnowledgeGraph) -> None:
        # Build a graph where node B is the critical chokepoint
        graph.add_tool("A")
        graph.add_tool("B")
        graph.add_tool("C")
        graph.add_tool("D")
        graph.add_edge("A", "B", EdgeType.CAN_CHAIN_TO)
        graph.add_edge("B", "C", EdgeType.CAN_CHAIN_TO)
        graph.add_edge("B", "D", EdgeType.CAN_CHAIN_TO)

        critical = graph.get_critical_nodes(top_n=3)
        assert len(critical) > 0
        # B should be the most central node
        assert critical[0][0] == "B"

    def test_get_dangerous_capabilities(self, graph: AttackKnowledgeGraph) -> None:
        safe_cap = AgentCapability(
            id="safe",
            name="safe_tool",
            type=CapabilityType.TOOL,
            dangerous=False,
        )
        dangerous_cap = AgentCapability(
            id="danger",
            name="danger_tool",
            type=CapabilityType.TOOL,
            dangerous=True,
        )
        graph.add_capability("safe", safe_cap)
        graph.add_capability("danger", dangerous_cap)

        dangerous = graph.get_dangerous_capabilities()
        assert len(dangerous) == 1
        assert dangerous[0][0] == "danger"

    def test_export_state(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("t1")
        graph.add_tool("t2")
        graph.add_edge("t1", "t2", EdgeType.CAN_CHAIN_TO)

        state = graph.export_state()
        assert state["stats"]["total_nodes"] == 2
        assert state["stats"]["total_edges"] == 1
        assert len(state["nodes"]) == 2
        assert len(state["edges"]) == 1
        assert "campaign_start" in state
        assert "campaign_duration_seconds" in state

    def test_export_import_roundtrip(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("t1", {"name": "search"})
        graph.add_tool("t2", {"name": "email"})
        graph.add_edge("t1", "t2", EdgeType.CAN_CHAIN_TO, {"risk": 0.5})

        state = graph.export_state()

        new_graph = AttackKnowledgeGraph()
        new_graph.import_state(state)

        assert new_graph.node_count == 2
        assert new_graph.edge_count == 1

    def test_density_single_node(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("only_node")
        state = graph.export_state()
        assert state["stats"]["density"] == 0.0

    def test_count_node_types(self, graph: AttackKnowledgeGraph) -> None:
        graph.add_tool("t1")
        graph.add_tool("t2")
        graph.add_vulnerability("v1", "high")
        graph.add_data_source("ds1")

        state = graph.export_state()
        node_types = state["stats"]["node_types"]
        assert node_types.get("tool") == 2
        assert node_types.get("vulnerability") == 1
        assert node_types.get("data_source") == 1
