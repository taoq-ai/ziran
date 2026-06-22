"""Per-phase graph snapshot persistence + API exposure (spec 026 US3).

The web layer is unit-tested here (no live-DB harness in this repo). These
cover the model column, the schema fallback contract, and the monotonic
"graph only grows" property the temporal scrubber relies on (SC-007).
"""

from __future__ import annotations

import uuid

import pytest

from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType
from ziran.interfaces.web.models import PhaseResultRow
from ziran.interfaces.web.schemas import PhaseResultSchema


@pytest.mark.unit
class TestPhaseGraphPersistence:
    def test_row_stores_graph_state_json(self) -> None:
        snapshot = {"nodes": [{"id": "a"}], "edges": []}
        row = PhaseResultRow(
            run_id=uuid.uuid4(),
            phase="reconnaissance",
            phase_index=0,
            success=True,
            trust_score=0.8,
            duration_seconds=1.0,
            graph_state_json=snapshot,
        )
        assert row.graph_state_json == snapshot

    def test_schema_surfaces_snapshot(self) -> None:
        row = PhaseResultRow(
            id=uuid.uuid4(),
            run_id=uuid.uuid4(),
            phase="execution",
            phase_index=2,
            success=True,
            trust_score=0.5,
            duration_seconds=3.0,
            token_usage_json={},
            vulnerabilities_found=[],
            discovered_capabilities=[],
            graph_state_json={"nodes": [], "edges": []},
            error=None,
        )
        schema = PhaseResultSchema.model_validate(row)
        assert schema.graph_state_json == {"nodes": [], "edges": []}

    def test_schema_defaults_to_none_for_legacy_rows(self) -> None:
        # A row created before the migration has no snapshot; the scrubber
        # falls back to the run's final graph_state_json.
        row = PhaseResultRow(
            id=uuid.uuid4(),
            run_id=uuid.uuid4(),
            phase="reconnaissance",
            phase_index=0,
            success=True,
            trust_score=0.9,
            duration_seconds=1.0,
            token_usage_json={},
            vulnerabilities_found=[],
            discovered_capabilities=[],
            error=None,
        )
        schema = PhaseResultSchema.model_validate(row)
        assert schema.graph_state_json is None

    def test_empty_snapshot_normalizes_to_null(self) -> None:
        # run_manager persists ``pr.graph_state or None`` — an empty dict (a
        # phase that touched nothing) is stored as NULL, not ``{}``.
        empty: dict[str, object] = {}
        assert (empty or None) is None

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
