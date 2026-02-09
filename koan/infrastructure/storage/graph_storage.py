"""Graph persistence — save and load knowledge graphs to/from JSON.

Provides file-based persistence for AttackKnowledgeGraph instances,
enabling campaign results to be saved for later analysis or report
regeneration.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from koan.application.knowledge_graph.graph import AttackKnowledgeGraph

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class GraphStorageError(Exception):
    """Raised when graph storage operations fail."""


class GraphStorage:
    """File-based persistence for AttackKnowledgeGraph.

    Saves and loads graph state as JSON files, supporting both
    individual campaign snapshots and incremental updates.

    Example:
        ```python
        storage = GraphStorage(output_dir=Path("./results"))
        storage.save(graph, campaign_id="campaign_123")
        loaded_graph = storage.load("campaign_123")
        ```
    """

    def __init__(self, output_dir: Path) -> None:
        """Initialize graph storage.

        Args:
            output_dir: Directory to store graph JSON files.
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        graph: AttackKnowledgeGraph,
        campaign_id: str,
    ) -> Path:
        """Save a knowledge graph to a JSON file.

        Args:
            graph: The knowledge graph to persist.
            campaign_id: Campaign identifier used as the filename.

        Returns:
            Path to the saved JSON file.

        Raises:
            GraphStorageError: If the save operation fails.
        """
        filepath = self.output_dir / f"{campaign_id}_graph.json"
        state = graph.export_state()

        try:
            with filepath.open("w") as f:
                json.dump(state, f, indent=2, default=str)
            logger.info("Graph saved to %s", filepath)
            return filepath
        except Exception as e:
            raise GraphStorageError(f"Failed to save graph to {filepath}: {e}") from e

    def load(self, campaign_id: str) -> AttackKnowledgeGraph:
        """Load a knowledge graph from a JSON file.

        Args:
            campaign_id: Campaign identifier to load.

        Returns:
            Reconstructed AttackKnowledgeGraph instance.

        Raises:
            GraphStorageError: If the load operation fails.
        """
        filepath = self.output_dir / f"{campaign_id}_graph.json"

        if not filepath.exists():
            raise GraphStorageError(f"Graph file not found: {filepath}")

        try:
            with filepath.open() as f:
                state = json.load(f)

            graph = AttackKnowledgeGraph()
            graph.import_state(state)
            logger.info(
                "Graph loaded from %s (%d nodes, %d edges)",
                filepath,
                graph.node_count,
                graph.edge_count,
            )
            return graph
        except json.JSONDecodeError as e:
            raise GraphStorageError(f"Invalid JSON in {filepath}: {e}") from e
        except Exception as e:
            raise GraphStorageError(f"Failed to load graph from {filepath}: {e}") from e

    def save_campaign_result(
        self,
        result: dict[str, Any],
        campaign_id: str,
    ) -> Path:
        """Save a full campaign result to JSON.

        Args:
            result: Campaign result dictionary.
            campaign_id: Campaign identifier.

        Returns:
            Path to the saved JSON file.
        """
        filepath = self.output_dir / f"{campaign_id}_result.json"

        try:
            with filepath.open("w") as f:
                json.dump(result, f, indent=2, default=str)
            logger.info("Campaign result saved to %s", filepath)
            return filepath
        except Exception as e:
            raise GraphStorageError(f"Failed to save campaign result to {filepath}: {e}") from e

    def list_campaigns(self) -> list[str]:
        """List all saved campaign IDs.

        Returns:
            List of campaign IDs found in the output directory.
        """
        campaigns = set()
        for filepath in self.output_dir.glob("*_graph.json"):
            campaign_id = filepath.stem.replace("_graph", "")
            campaigns.add(campaign_id)
        return sorted(campaigns)
