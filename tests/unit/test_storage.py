"""Unit tests for graph storage."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from koan.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType
from koan.infrastructure.storage.graph_storage import GraphStorage, GraphStorageError

if TYPE_CHECKING:
    from pathlib import Path


class TestGraphStorage:
    """Tests for GraphStorage persistence."""

    @pytest.fixture
    def storage(self, tmp_path: Path) -> GraphStorage:
        return GraphStorage(output_dir=tmp_path)

    @pytest.fixture
    def sample_graph(self) -> AttackKnowledgeGraph:
        graph = AttackKnowledgeGraph()
        graph.add_tool("tool_a", {"name": "search"})
        graph.add_tool("tool_b", {"name": "email"})
        graph.add_edge("tool_a", "tool_b", EdgeType.CAN_CHAIN_TO)
        return graph

    def test_save_and_load(
        self,
        storage: GraphStorage,
        sample_graph: AttackKnowledgeGraph,
    ) -> None:
        filepath = storage.save(sample_graph, "test_campaign")
        assert filepath.exists()
        assert filepath.suffix == ".json"

        loaded = storage.load("test_campaign")
        assert loaded.node_count == 2
        assert loaded.edge_count == 1

    def test_load_nonexistent(self, storage: GraphStorage) -> None:
        with pytest.raises(GraphStorageError, match="not found"):
            storage.load("nonexistent_campaign")

    def test_list_campaigns(
        self,
        storage: GraphStorage,
        sample_graph: AttackKnowledgeGraph,
    ) -> None:
        storage.save(sample_graph, "campaign_a")
        storage.save(sample_graph, "campaign_b")

        campaigns = storage.list_campaigns()
        assert "campaign_a" in campaigns
        assert "campaign_b" in campaigns
        assert len(campaigns) == 2

    def test_save_campaign_result(self, storage: GraphStorage) -> None:
        result = {"campaign_id": "test", "vulnerabilities": 5}
        filepath = storage.save_campaign_result(result, "test_result")
        assert filepath.exists()

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        nested_dir = tmp_path / "a" / "b" / "c"
        GraphStorage(output_dir=nested_dir)
        assert nested_dir.exists()
