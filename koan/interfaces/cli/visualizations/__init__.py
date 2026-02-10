"""Interactive graph visualization using Plotly.

Generates self-contained HTML visualizations of the attack knowledge
graph, highlighting dangerous tool chains with color-coded edges and
interactive tooltips.

Uses :mod:`plotly` and :mod:`networkx` for layout computation.
Plotly is an optional dependency — the visualizer degrades gracefully
if it is not installed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import networkx as nx

if TYPE_CHECKING:
    from koan.application.knowledge_graph.graph import AttackKnowledgeGraph
    from koan.domain.entities.capability import DangerousChain

logger = logging.getLogger(__name__)

# ── Node styling ──────────────────────────────────────────────────────

_NODE_COLORS: dict[str, str] = {
    "tool": "#10b981",
    "capability": "#3b82f6",
    "vulnerability": "#ef4444",
    "data_source": "#f59e0b",
    "phase": "#8b5cf6",
    "agent_state": "#6b7280",
}

_NODE_SYMBOLS: dict[str, str] = {
    "tool": "diamond",
    "capability": "circle",
    "vulnerability": "triangle-up",
    "data_source": "square",
    "phase": "hexagon",
    "agent_state": "circle",
}

_EDGE_COLORS: dict[str, str] = {
    "uses_tool": "#3b82f6",
    "accesses_data": "#f59e0b",
    "trusts": "#10b981",
    "enables": "#ef4444",
    "can_chain_to": "#f97316",
    "discovered_in": "#8b5cf6",
    "exploits": "#dc2626",
    "leads_to": "#ec4899",
}

_RISK_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}


class GraphVisualizer:
    """Creates interactive Plotly visualizations of the knowledge graph.

    Example::

        viz = GraphVisualizer()
        fig = viz.create_interactive_viz(graph, dangerous_chains)
        viz.export_html("report_graph.html")
    """

    def __init__(self) -> None:
        self._figure: Any | None = None

    def create_interactive_viz(
        self,
        graph: AttackKnowledgeGraph,
        dangerous_chains: list[DangerousChain] | None = None,
    ) -> Any:
        """Build an interactive Plotly figure of the knowledge graph.

        Args:
            graph: The attack knowledge graph.
            dangerous_chains: Optional list of dangerous chains to highlight.

        Returns:
            A :class:`plotly.graph_objects.Figure` instance (returned as
            ``Any`` so that Plotly remains an optional dependency).

        Raises:
            ImportError: If ``plotly`` is not installed.
        """
        try:
            import plotly.graph_objects as go
        except ImportError as exc:
            raise ImportError(
                "Plotly is required for graph visualization. "
                "Install it with: pip install plotly"
            ) from exc

        nx_graph = graph.graph

        if nx_graph.number_of_nodes() == 0:
            fig = go.Figure()
            fig.update_layout(
                title="Knowledge Graph (empty)",
                annotations=[
                    {
                        "text": "No nodes in graph",
                        "xref": "paper",
                        "yref": "paper",
                        "showarrow": False,
                        "font": {"size": 20},
                    }
                ],
            )
            self._figure = fig
            return fig

        # Compute layout
        pos = nx.spring_layout(nx_graph, seed=42, k=2.0)

        # Build dangerous-chain edge set for highlighting
        chain_edges: set[tuple[str, str]] = set()
        chain_risk_map: dict[tuple[str, str], str] = {}
        if dangerous_chains:
            for chain in dangerous_chains:
                for i in range(len(chain.graph_path) - 1):
                    edge = (chain.graph_path[i], chain.graph_path[i + 1])
                    chain_edges.add(edge)
                    existing = chain_risk_map.get(edge)
                    if existing is None or _risk_rank(chain.risk_level) < _risk_rank(existing):
                        chain_risk_map[edge] = chain.risk_level

        # ── Edge traces ───────────────────────────────────────────
        edge_traces: list[Any] = []

        for u, v, data in nx_graph.edges(data=True):
            if u not in pos or v not in pos:
                continue

            x0, y0 = pos[u]
            x1, y1 = pos[v]

            is_dangerous = (u, v) in chain_edges
            risk = chain_risk_map.get((u, v))
            edge_type = data.get("edge_type", "unknown")

            if is_dangerous and risk:
                color = _RISK_COLORS.get(risk, "#ef4444")
                width = 3.5
            else:
                color = _EDGE_COLORS.get(edge_type, "#9ca3af")
                width = 1.5

            edge_traces.append(
                go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode="lines",
                    line={"width": width, "color": color},
                    hoverinfo="text",
                    text=f"{u} → {v}<br>Type: {edge_type}",
                    showlegend=False,
                )
            )

        # ── Node traces (grouped by type for legend) ──────────────
        nodes_by_type: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for n, d in nx_graph.nodes(data=True):
            ntype = d.get("node_type", "unknown")
            nodes_by_type.setdefault(ntype, []).append((n, d))

        node_traces: list[Any] = []

        for ntype, nodes in nodes_by_type.items():
            xs, ys, texts, hovers = [], [], [], []
            for nid, ndata in nodes:
                if nid not in pos:
                    continue
                x, y = pos[nid]
                xs.append(x)
                ys.append(y)
                texts.append(nid)

                hover_lines = [f"<b>{nid}</b>", f"Type: {ntype}"]
                if ndata.get("dangerous"):
                    hover_lines.append("<b>⚠️ DANGEROUS</b>")
                if ndata.get("severity"):
                    hover_lines.append(f"Severity: {ndata['severity']}")
                hovers.append("<br>".join(hover_lines))

            color = _NODE_COLORS.get(ntype, "#6b7280")
            symbol = _NODE_SYMBOLS.get(ntype, "circle")

            node_traces.append(
                go.Scatter(
                    x=xs,
                    y=ys,
                    mode="markers+text",
                    marker={
                        "size": 14,
                        "color": color,
                        "symbol": symbol,
                        "line": {"width": 2, "color": "#ffffff"},
                    },
                    text=texts,
                    textposition="top center",
                    textfont={"size": 9},
                    hovertext=hovers,
                    hoverinfo="text",
                    name=ntype.replace("_", " ").title(),
                )
            )

        # ── Assemble figure ───────────────────────────────────────
        fig = go.Figure(data=edge_traces + node_traces)

        chain_annotation = ""
        if dangerous_chains:
            n_crit = sum(1 for c in dangerous_chains if c.risk_level == "critical")
            chain_annotation = (
                f" | {len(dangerous_chains)} dangerous chains "
                f"({n_crit} critical)"
            )

        fig.update_layout(
            title={
                "text": (
                    f"KOAN Attack Knowledge Graph — "
                    f"{nx_graph.number_of_nodes()} nodes, "
                    f"{nx_graph.number_of_edges()} edges"
                    f"{chain_annotation}"
                ),
                "font": {"size": 16},
            },
            showlegend=True,
            hovermode="closest",
            paper_bgcolor="#0f172a",
            plot_bgcolor="#1e293b",
            font={"color": "#e2e8f0"},
            legend={
                "bgcolor": "rgba(30,41,59,0.8)",
                "font": {"color": "#e2e8f0"},
            },
            xaxis={
                "showgrid": False,
                "zeroline": False,
                "showticklabels": False,
            },
            yaxis={
                "showgrid": False,
                "zeroline": False,
                "showticklabels": False,
            },
            margin={"l": 20, "r": 20, "t": 60, "b": 20},
        )

        self._figure = fig
        return fig

    def export_html(self, filepath: str) -> str:
        """Export the current figure to a standalone HTML file.

        Args:
            filepath: Path for the output HTML file.

        Returns:
            The filepath that was written.

        Raises:
            RuntimeError: If no figure has been created yet.
        """
        if self._figure is None:
            raise RuntimeError("Call create_interactive_viz() first")

        self._figure.write_html(filepath, include_plotlyjs="cdn")
        logger.info("Graph visualization exported to %s", filepath)
        return filepath

    def to_html_div(self) -> str:
        """Return the figure as an embeddable HTML ``<div>`` string.

        Useful for embedding inside larger HTML reports.
        """
        if self._figure is None:
            raise RuntimeError("Call create_interactive_viz() first")

        return str(self._figure.to_html(full_html=False, include_plotlyjs="cdn"))


# ── Helpers ────────────────────────────────────────────────────────────

_RISK_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _risk_rank(level: str) -> int:
    return _RISK_RANK.get(level, 99)
