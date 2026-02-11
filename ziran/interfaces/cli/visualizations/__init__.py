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
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
    from ziran.domain.entities.capability import DangerousChain

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
                "Plotly is required for graph visualization. Install it with: pip install plotly"
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

        # Compute hierarchical layout grouped by phase
        pos = _hierarchical_phase_layout(nx_graph)

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
            chain_annotation = f" | {len(dangerous_chains)} dangerous chains ({n_crit} critical)"

        fig.update_layout(
            title={
                "text": (
                    f"ZIRAN Attack Knowledge Graph — "
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


# ── Phase ordering for hierarchical layout ─────────────────────────────

_PHASE_ORDER: list[str] = [
    "reconnaissance",
    "trust_building",
    "capability_mapping",
    "vulnerability_discovery",
    "exploitation_setup",
    "execution",
    "persistence",
    "exfiltration",
]


def _hierarchical_phase_layout(
    graph: nx.MultiDiGraph,
) -> dict[str, tuple[float, float]]:
    """Compute a left-to-right hierarchical layout grouped by phase.

    Nodes discovered in a phase are placed in the same vertical band.
    Within each band, nodes are stacked vertically by type so that the
    layout "tells a story" from reconnaissance → exfiltration.

    Nodes without a ``discovered_in`` edge to a phase node fall back to
    a spring-layout column on the far left (capabilities / tools).
    """
    # Map node → earliest phase via DISCOVERED_IN or EXECUTED_IN edges
    node_phase: dict[str, str] = {}
    for _u, v, data in graph.edges(data=True):
        edge_type = data.get("edge_type", "")
        if edge_type in ("discovered_in", "executed_in"):
            target_data = graph.nodes.get(v, {})
            if target_data.get("node_type") == "phase":
                phase_name = target_data.get("name", v)
                if _u not in node_phase:
                    node_phase[_u] = phase_name

    # Also assign phase nodes themselves
    for n, d in graph.nodes(data=True):
        if d.get("node_type") == "phase":
            node_phase[n] = d.get("name", n)

    # Build columns: index → list of nodes
    phase_to_col: dict[str, int] = {p: i + 1 for i, p in enumerate(_PHASE_ORDER)}

    columns: dict[int, list[str]] = {0: []}  # col 0 = unassigned
    for col_idx in phase_to_col.values():
        columns[col_idx] = []

    for n in graph.nodes():
        phase = node_phase.get(n)
        col = phase_to_col.get(phase, 0) if phase else 0
        columns[col].append(n)

    # Sort nodes within each column by type for readability
    _type_order = {"phase": 0, "capability": 1, "tool": 2, "vulnerability": 3, "data_source": 4}

    pos: dict[str, tuple[float, float]] = {}
    max_col = max(columns.keys()) if columns else 0
    x_spacing = 2.0

    for col_idx, nodes in columns.items():
        if not nodes:
            continue
        nodes.sort(key=lambda n: _type_order.get(graph.nodes[n].get("node_type", ""), 5))
        y_spacing = 1.2
        y_start = -(len(nodes) - 1) * y_spacing / 2
        x = col_idx * x_spacing
        for i, n in enumerate(nodes):
            pos[n] = (x, y_start + i * y_spacing)

    # Fall back to spring layout for anything missed
    missing = [n for n in graph.nodes() if n not in pos]
    if missing:
        sub = graph.subgraph(missing)
        spring = nx.spring_layout(sub, seed=42, k=1.5)
        x_offset = (max_col + 1) * x_spacing
        for n, (sx, sy) in spring.items():
            pos[n] = (sx + x_offset, sy)

    return pos
