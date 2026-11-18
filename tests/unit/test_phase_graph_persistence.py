"""Per-phase graph snapshots (spec 026 US3).

Each phase records ``AttackKnowledgeGraph.export_state()``. Successive
snapshots only grow, so a renderer that replays them only ever adds nodes
(SC-007).
"""

from __future__ import annotations

import pytest

from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType


@pytest.mark.unit
class TestPhaseGraphPersistence:
    def test_snapshots_are_monotonic_supersets(self) -> None:
        # Each successive phase snapshot must be a superset of the previous one
        # so the scrubber only ever adds nodes (SC-007).
        graph = AttackKnowledgeGraph()
        graph.add_tool("recon_tool")
        phase1 = {n["id"] for n in graph.export_state()["nodes"]}

        graph.add_vulnerability("vuln_1", "high")
        graph.add_edge("recon_tool", "vuln_1", EdgeType.EXPLOITS)
        phase2 = {n["id"] for n in graph.export_state()["nodes"]}

        assert phase1 <= phase2
        assert "vuln_1" in phase2 and "vuln_1" not in phase1
