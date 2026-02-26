"""Tests for GraphVisualizer — interactive Plotly graph visualization."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import networkx as nx
import pytest

from ziran.interfaces.cli.visualizations import (
    GraphVisualizer,
    _hierarchical_phase_layout,
    _risk_rank,
)

# ── Helpers ──────────────────────────────────────────────────────────

def _empty_graph() -> MagicMock:
    """Graph wrapper whose .graph is an empty MultiDiGraph."""
    g = MagicMock()
    g.graph = nx.MultiDiGraph()
    return g


def _small_graph() -> MagicMock:
    """Graph wrapper whose .graph has a few different node types."""
    g = MagicMock()
    mg = nx.MultiDiGraph()
    mg.add_node("tool_a", node_type="tool", name="tool_a")
    mg.add_node("cap_b", node_type="capability", name="cap_b")
    mg.add_node("vuln_c", node_type="vulnerability", name="vuln_c", severity="critical")
    mg.add_node("phase_recon", node_type="phase", name="reconnaissance")
    mg.add_edge("tool_a", "cap_b", edge_type="uses_tool")
    mg.add_edge("cap_b", "vuln_c", edge_type="exploits")
    mg.add_edge("tool_a", "phase_recon", edge_type="discovered_in")
    g.graph = mg
    return g


def _mock_plotly():
    """Patch plotly so tests work without it installed."""
    go = MagicMock()
    scatter_cls = MagicMock()
    go.Scatter = scatter_cls
    fig = MagicMock()
    go.Figure.return_value = fig
    fig.update_layout = MagicMock()
    fig.write_html = MagicMock()
    fig.to_html = MagicMock(return_value="<div>graph</div>")
    return go, fig


# ── GraphVisualizer tests ───────────────────────────────────────────

class TestGraphVisualizer:
    def test_empty_graph(self) -> None:
        go, _fig = _mock_plotly()
        with patch.dict("sys.modules", {"plotly": MagicMock(), "plotly.graph_objects": go}):
            viz = GraphVisualizer()
            result = viz.create_interactive_viz(_empty_graph())
        assert result is not None

    def test_small_graph_no_chains(self) -> None:
        go, _fig = _mock_plotly()
        with patch.dict("sys.modules", {"plotly": MagicMock(), "plotly.graph_objects": go}):
            viz = GraphVisualizer()
            result = viz.create_interactive_viz(_small_graph())
        assert result is not None

    def test_small_graph_with_chains(self) -> None:
        go, _fig = _mock_plotly()
        chain = MagicMock()
        chain.graph_path = ["tool_a", "cap_b", "vuln_c"]
        chain.risk_level = "critical"
        with patch.dict("sys.modules", {"plotly": MagicMock(), "plotly.graph_objects": go}):
            viz = GraphVisualizer()
            result = viz.create_interactive_viz(_small_graph(), dangerous_chains=[chain])
        assert result is not None

    def test_export_html_no_figure(self) -> None:
        viz = GraphVisualizer()
        with pytest.raises(RuntimeError, match="create_interactive_viz"):
            viz.export_html("output.html")

    def test_export_html_success(self) -> None:
        go, _fig = _mock_plotly()
        with patch.dict("sys.modules", {"plotly": MagicMock(), "plotly.graph_objects": go}):
            viz = GraphVisualizer()
            viz.create_interactive_viz(_small_graph())
        # Now _figure is set
        path = viz.export_html("/tmp/test_viz.html")
        assert path == "/tmp/test_viz.html"

    def test_to_html_div_no_figure(self) -> None:
        viz = GraphVisualizer()
        with pytest.raises(RuntimeError, match="create_interactive_viz"):
            viz.to_html_div()

    def test_to_html_div_success(self) -> None:
        go, _fig = _mock_plotly()
        with patch.dict("sys.modules", {"plotly": MagicMock(), "plotly.graph_objects": go}):
            viz = GraphVisualizer()
            viz.create_interactive_viz(_small_graph())
        html = viz.to_html_div()
        assert isinstance(html, str)


# ── _hierarchical_phase_layout ───────────────────────────────────────

class TestHierarchicalLayout:
    def test_empty_graph(self) -> None:
        pos = _hierarchical_phase_layout(nx.MultiDiGraph())
        assert pos == {}

    def test_simple_layout(self) -> None:
        g = nx.MultiDiGraph()
        g.add_node("phase_recon", node_type="phase", name="reconnaissance")
        g.add_node("tool_a", node_type="tool")
        g.add_edge("tool_a", "phase_recon", edge_type="discovered_in")
        pos = _hierarchical_phase_layout(g)
        assert "phase_recon" in pos
        assert "tool_a" in pos

    def test_unassigned_nodes_get_col_zero(self) -> None:
        g = nx.MultiDiGraph()
        g.add_node("orphan", node_type="tool")
        pos = _hierarchical_phase_layout(g)
        assert "orphan" in pos
        # Column 0 means x ≈ 0
        assert pos["orphan"][0] == pytest.approx(0.0)


# ── _risk_rank ───────────────────────────────────────────────────────

class TestRiskRank:
    @pytest.mark.parametrize(
        "level,expected",
        [("critical", 0), ("high", 1), ("medium", 2), ("low", 3), ("unknown", 99)],
    )
    def test_known_levels(self, level: str, expected: int) -> None:
        assert _risk_rank(level) == expected


# ── graph_viz.py re-export ───────────────────────────────────────────


class TestGraphVizReExport:
    def test_imports(self) -> None:
        from ziran.interfaces.cli.visualizations.graph_viz import GraphVisualizer

        assert GraphVisualizer is not None
