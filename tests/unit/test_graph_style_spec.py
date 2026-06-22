"""Unit + parity tests for the canonical graph style spec (spec 026 US4)."""

from __future__ import annotations

import pytest

from ziran.application.knowledge_graph.graph import EdgeType, NodeType
from ziran.interfaces.graph_style.spec import GraphStyleSpec, load_graph_style


def _known_node_types() -> set[str]:
    return {v for k, v in vars(NodeType).items() if not k.startswith("_") and isinstance(v, str)}


def _known_edge_types() -> set[str]:
    return {v for k, v in vars(EdgeType).items() if not k.startswith("_") and isinstance(v, str)}


@pytest.mark.unit
class TestGraphStyleSpec:
    """The spec loads, validates, and covers every known node/edge type."""

    def test_loads_and_validates(self) -> None:
        spec = load_graph_style()
        assert isinstance(spec, GraphStyleSpec)
        assert spec.version

    def test_covers_all_node_types(self) -> None:
        spec = load_graph_style()
        assert set(spec.node_types) == _known_node_types()

    def test_covers_all_edge_types(self) -> None:
        spec = load_graph_style()
        assert set(spec.edge_types) == _known_edge_types()

    def test_phase_order_is_unique_and_nonempty(self) -> None:
        order = load_graph_style().phase_order
        assert order
        assert len(order) == len(set(order))

    def test_attack_edge_types_are_known(self) -> None:
        spec = load_graph_style()
        assert set(spec.attack_edge_types).issubset(set(spec.edge_types))
        assert all(spec.is_attack_edge(t) for t in spec.attack_edge_types)

    def test_size_for_centrality_bounds(self) -> None:
        spec = load_graph_style()
        lo, hi = spec.size_encoding.min_size, spec.size_encoding.max_size
        assert spec.size_for_centrality(0.0) == pytest.approx(lo)
        assert spec.size_for_centrality(1.0) == pytest.approx(hi)
        # Graceful clamping for missing / out-of-range values.
        assert spec.size_for_centrality(None) == pytest.approx(lo)
        assert spec.size_for_centrality(2.0) == pytest.approx(hi)
        assert spec.size_for_centrality(-1.0) == pytest.approx(lo)

    def test_node_style_fallback(self) -> None:
        spec = load_graph_style()
        # Unknown type falls back to the neutral agent_state style.
        assert spec.node_style("does_not_exist") == spec.node_types["agent_state"]

    def test_edge_style_fallback(self) -> None:
        spec = load_graph_style()
        fallback = spec.edge_style("does_not_exist")
        assert fallback.color  # synthesized neutral default, never raises

    def test_severity_color_case_insensitive(self) -> None:
        spec = load_graph_style()
        assert spec.severity_color("CRITICAL") == spec.severity_ramp["critical"]
        assert spec.severity_color(None) is None
        assert spec.severity_color("nonsense") is None

    def test_node_size_uses_base_as_floor(self) -> None:
        spec = load_graph_style()
        vuln_base = spec.node_types["vulnerability"].base_size
        # Zero centrality falls back to the type's base size (the floor)...
        assert spec.node_size("vulnerability", 0.0) == pytest.approx(vuln_base)
        # ...and a pivotal node grows up to the max size.
        assert spec.node_size("vulnerability", 1.0) == pytest.approx(spec.size_encoding.max_size)

    def test_phase_level_ordering_and_fallback(self) -> None:
        spec = load_graph_style()
        assert spec.phase_level(spec.phase_order[0]) == 1
        assert spec.phase_level(spec.phase_order[-1]) == len(spec.phase_order)
        assert spec.phase_level(None) == 0  # unassigned band
        assert spec.phase_level("not_a_real_phase") == 0  # unknown → unassigned
