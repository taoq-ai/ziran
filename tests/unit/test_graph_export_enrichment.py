"""Unit tests for ``export_state`` importance/phase enrichment (spec 026)."""

from __future__ import annotations

import pytest

from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType, NodeType


@pytest.mark.unit
class TestExportStateEnrichment:
    """``export_state`` attaches normalized centrality and discovery phase."""

    def test_centrality_attached_and_normalized(self) -> None:
        graph = AttackKnowledgeGraph()
        # A linear chain a -> b -> c makes ``b`` the chokepoint.
        graph.add_tool("a")
        graph.add_tool("b")
        graph.add_tool("c")
        graph.add_edge("a", "b", EdgeType.CAN_CHAIN_TO)
        graph.add_edge("b", "c", EdgeType.CAN_CHAIN_TO)

        nodes = {n["id"]: n for n in graph.export_state()["nodes"]}

        assert all("centrality" in n for n in nodes.values())
        # Every value is normalized into [0, 1] with the chokepoint at the top.
        assert all(0.0 <= n["centrality"] <= 1.0 for n in nodes.values())
        assert nodes["b"]["centrality"] == pytest.approx(1.0)
        assert nodes["a"]["centrality"] == pytest.approx(0.0)

    def test_phase_derived_from_discovery_edge(self) -> None:
        graph = AttackKnowledgeGraph()
        graph.graph.add_node("phase_recon", node_type=NodeType.PHASE, name="reconnaissance")
        graph.add_tool("tool_x")
        graph.add_edge("tool_x", "phase_recon", EdgeType.DISCOVERED_IN)

        nodes = {n["id"]: n for n in graph.export_state()["nodes"]}

        assert nodes["tool_x"]["phase"] == "reconnaissance"
        # The phase node is attributed to itself.
        assert nodes["phase_recon"]["phase"] == "reconnaissance"

    def test_unattributed_node_has_no_phase_and_default_centrality(self) -> None:
        graph = AttackKnowledgeGraph()
        graph.add_tool("lonely")

        node = graph.export_state()["nodes"][0]

        assert node["id"] == "lonely"
        assert "phase" not in node  # unassigned — never dropped
        assert node["centrality"] == 0.0  # graceful default for tiny graphs

    def test_enrichment_survives_export_cache(self) -> None:
        graph = AttackKnowledgeGraph()
        graph.add_tool("a")
        graph.add_tool("b")
        graph.add_tool("c")
        graph.add_edge("a", "b", EdgeType.CAN_CHAIN_TO)
        graph.add_edge("b", "c", EdgeType.CAN_CHAIN_TO)

        first = {n["id"]: n["centrality"] for n in graph.export_state()["nodes"]}
        # Second call returns the cached state — enrichment must persist.
        second = {n["id"]: n["centrality"] for n in graph.export_state()["nodes"]}

        assert first == second
