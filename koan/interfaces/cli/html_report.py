"""Interactive HTML report with knowledge graph visualization.

Generates a self-contained HTML file that embeds:
- vis-network for interactive graph rendering
- Campaign summary sidebar with phase timeline
- Attack path highlighting
- Node/edge detail panel on click

All JavaScript and CSS are inlined — no external dependencies
beyond the vis-network CDN.
"""

from __future__ import annotations

import html
import json
from typing import Any

# ── Node appearance by type ────────────────────────────────────────────

_NODE_COLORS: dict[str, dict[str, str | dict[str, str]]] = {
    "capability": {
        "background": "#3b82f6",
        "border": "#1d4ed8",
        "highlight": {"background": "#60a5fa", "border": "#2563eb"},
    },
    "tool": {
        "background": "#10b981",
        "border": "#047857",
        "highlight": {"background": "#34d399", "border": "#059669"},
    },
    "vulnerability": {
        "background": "#ef4444",
        "border": "#b91c1c",
        "highlight": {"background": "#f87171", "border": "#dc2626"},
    },
    "data_source": {
        "background": "#f59e0b",
        "border": "#b45309",
        "highlight": {"background": "#fbbf24", "border": "#d97706"},
    },
    "phase": {
        "background": "#8b5cf6",
        "border": "#6d28d9",
        "highlight": {"background": "#a78bfa", "border": "#7c3aed"},
    },
    "agent_state": {
        "background": "#6b7280",
        "border": "#374151",
        "highlight": {"background": "#9ca3af", "border": "#4b5563"},
    },
}

_NODE_SHAPES: dict[str, str] = {
    "capability": "dot",
    "tool": "diamond",
    "vulnerability": "triangle",
    "data_source": "square",
    "phase": "hexagon",
    "agent_state": "ellipse",
}

_NODE_SIZES: dict[str, int] = {
    "capability": 18,
    "tool": 20,
    "vulnerability": 25,
    "data_source": 18,
    "phase": 22,
    "agent_state": 16,
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

_EDGE_DASHES: dict[str, bool] = {
    "enables": True,
    "can_chain_to": True,
    "exploits": True,
}


# ── Converter ──────────────────────────────────────────────────────────


def graph_state_to_vis(graph_state: dict[str, Any]) -> dict[str, Any]:
    """Convert graph export_state() dict to vis-network nodes/edges.

    Args:
        graph_state: Dictionary from ``AttackKnowledgeGraph.export_state()``.

    Returns:
        ``{"nodes": [...], "edges": [...]}`` ready for vis-network DataSets.
    """
    vis_nodes: list[dict[str, Any]] = []
    vis_edges: list[dict[str, Any]] = []

    for node in graph_state.get("nodes", []):
        node_type = node.get("node_type", "agent_state")
        colors = _NODE_COLORS.get(node_type, _NODE_COLORS["agent_state"])
        label = node.get("name", node["id"])
        if len(label) > 30:
            label = label[:27] + "…"

        vis_node: dict[str, Any] = {
            "id": node["id"],
            "label": label,
            "title": _build_node_tooltip(node),
            "shape": _NODE_SHAPES.get(node_type, "dot"),
            "size": _NODE_SIZES.get(node_type, 16),
            "color": colors,
            "font": {"color": "#f8fafc", "size": 12},
            "nodeType": node_type,
        }
        # Vulnerability nodes get a red border glow
        if node_type == "vulnerability":
            vis_node["borderWidth"] = 3
            vis_node["shadow"] = {"enabled": True, "color": "rgba(239,68,68,0.5)", "size": 12}

        vis_nodes.append(vis_node)

    for idx, edge in enumerate(graph_state.get("edges", [])):
        edge_type = edge.get("edge_type", "")
        vis_edge: dict[str, Any] = {
            "id": f"e{idx}",
            "from": edge["source"],
            "to": edge["target"],
            "label": edge_type.replace("_", " "),
            "arrows": "to",
            "color": {"color": _EDGE_COLORS.get(edge_type, "#94a3b8"), "opacity": 0.8},
            "font": {"size": 10, "color": "#94a3b8", "strokeWidth": 0, "align": "middle"},
            "smooth": {"type": "curvedCW", "roundness": 0.15},
            "edgeType": edge_type,
        }
        if _EDGE_DASHES.get(edge_type, False):
            vis_edge["dashes"] = True
        if edge_type in ("exploits", "enables"):
            vis_edge["width"] = 2.5
        else:
            vis_edge["width"] = 1.5
        vis_edges.append(vis_edge)

    return {"nodes": vis_nodes, "edges": vis_edges}


def _build_node_tooltip(node: dict[str, Any]) -> str:
    """Build a rich HTML tooltip for a graph node."""
    parts = [f"<b>{html.escape(str(node.get('name', node['id'])))}</b>"]
    parts.append(f"Type: {node.get('node_type', 'unknown')}")

    if node.get("risk_score") is not None:
        parts.append(f"Risk: {node['risk_score']:.2f}")
    if node.get("severity"):
        parts.append(f"Severity: {node['severity']}")
    if node.get("category"):
        parts.append(f"Category: {node['category']}")
    if node.get("dangerous"):
        parts.append("⚠️ Dangerous capability")
    if node.get("description"):
        desc = str(node["description"])
        if len(desc) > 120:
            desc = desc[:117] + "…"
        parts.append(f"<i>{html.escape(desc)}</i>")

    return "<br>".join(parts)


# ── HTML template ──────────────────────────────────────────────────────


def build_html_report(
    result_data: dict[str, Any],
    graph_state: dict[str, Any],
    critical_paths: list[list[str]] | None = None,
) -> str:
    """Render a self-contained interactive HTML report.

    Args:
        result_data: CampaignResult serialised via ``model_dump(mode='json')``.
        graph_state: Dictionary from ``AttackKnowledgeGraph.export_state()``
                     (or from the last ``PhaseResult.graph_state``).
        critical_paths: Optional explicit critical paths list; falls back
                        to ``result_data["critical_paths"]``.

    Returns:
        Complete HTML string ready to be written to a file.
    """
    vis_data = graph_state_to_vis(graph_state)
    paths = critical_paths or result_data.get("critical_paths", [])
    stats = graph_state.get("stats", {})

    campaign_id = result_data.get("campaign_id", "unknown")
    target_agent = result_data.get("target_agent", "unknown")
    total_vulns = result_data.get("total_vulnerabilities", 0)
    trust_score = result_data.get("final_trust_score", 0)
    success = result_data.get("success", False)
    phases = result_data.get("phases_executed", [])
    token_usage = result_data.get("token_usage", {})
    coverage_level = result_data.get("coverage_level", "")

    # Build phase timeline HTML
    phases_html = _build_phases_html(phases)
    # Build attack paths HTML
    paths_html = _build_paths_html(paths)
    # Build vulnerability list HTML
    vulns_html = _build_vulns_html(phases)
    # Build legend HTML
    legend_html = _build_legend_html()
    # Build attack log HTML
    attack_results = result_data.get("attack_results", [])
    attack_log_html = _build_attack_log_html(attack_results)
    # Build OWASP compliance HTML
    owasp_html = _build_owasp_html(attack_results, phases)

    return _HTML_TEMPLATE.format(
        campaign_id=html.escape(campaign_id),
        target_agent=html.escape(target_agent),
        total_vulns=total_vulns,
        trust_score=f"{trust_score:.2f}",
        trust_pct=int(trust_score * 100),
        success_label="VULNERABLE" if success else "PASSED",
        success_class="danger" if success else "safe",
        total_nodes=stats.get("total_nodes", 0),
        total_edges=stats.get("total_edges", 0),
        density=f"{stats.get('density', 0):.3f}",
        num_paths=len(paths),
        prompt_tokens=f"{token_usage.get('prompt_tokens', 0):,}",
        completion_tokens=f"{token_usage.get('completion_tokens', 0):,}",
        total_tokens=f"{token_usage.get('total_tokens', 0):,}",
        coverage_level=html.escape(coverage_level or "standard"),
        phases_html=phases_html,
        paths_html=paths_html,
        vulns_html=vulns_html,
        legend_html=legend_html,
        attack_log_html=attack_log_html,
        owasp_html=owasp_html,
        vis_nodes_json=json.dumps(vis_data["nodes"]),
        vis_edges_json=json.dumps(vis_data["edges"]),
        critical_paths_json=json.dumps(paths),
    )


# ── HTML fragment builders ─────────────────────────────────────────────


def _build_phases_html(phases: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for p in phases:
        phase_name = p.get("phase", "unknown").replace("_", " ").title()
        vulns = p.get("vulnerabilities_found", [])
        score = p.get("trust_score", 0)
        duration = p.get("duration_seconds", 0)
        status_cls = "phase-danger" if vulns else "phase-ok"
        icon = "🔴" if vulns else "🟢"

        parts.append(
            f'<div class="phase-card {status_cls}">'
            f'  <div class="phase-header">{icon} {html.escape(phase_name)}</div>'
            f'  <div class="phase-meta">'
            f"    <span>Trust: {score:.2f}</span>"
            f"    <span>{duration:.1f}s</span>"
            f"    <span>{len(vulns)} vuln{'s' if len(vulns) != 1 else ''}</span>"
            f"  </div>"
            f"</div>"
        )
    return "\n".join(parts)


def _build_paths_html(paths: list[list[str]]) -> str:
    if not paths:
        return '<p class="muted">No critical attack paths found.</p>'
    parts: list[str] = []
    for i, path in enumerate(paths[:20]):
        arrow_path = " → ".join(html.escape(str(n)) for n in path)
        parts.append(
            f'<div class="path-item" data-path-index="{i}" onclick="highlightPath({i})">'
            f'  <span class="path-num">#{i + 1}</span> {arrow_path}'
            f"</div>"
        )
    if len(paths) > 20:
        parts.append(f'<p class="muted">…and {len(paths) - 20} more paths</p>')
    return "\n".join(parts)


def _build_vulns_html(phases: list[dict[str, Any]]) -> str:
    vulns_seen: list[dict[str, Any]] = []
    for p in phases:
        artifacts = p.get("artifacts", {})
        for vid in p.get("vulnerabilities_found", []):
            art = artifacts.get(vid, {})
            vulns_seen.append(
                {
                    "id": vid,
                    "name": art.get("name", vid),
                    "severity": art.get("severity", "unknown"),
                    "category": art.get("category", "unknown"),
                    "phase": p.get("phase", "unknown"),
                }
            )

    if not vulns_seen:
        return '<p class="muted">No vulnerabilities discovered.</p>'

    parts: list[str] = []
    for v in vulns_seen:
        sev = v["severity"].lower()
        sev_cls = (
            "sev-critical"
            if sev in ("critical", "high")
            else "sev-medium"
            if sev == "medium"
            else "sev-low"
        )
        parts.append(
            f'<div class="vuln-card">'
            f'  <div class="vuln-name">{html.escape(v["name"])}</div>'
            f'  <div class="vuln-meta">'
            f'    <span class="sev-badge {sev_cls}">{html.escape(v["severity"])}</span>'
            f"    <span>{html.escape(v['category'])}</span>"
            f'    <span class="muted">in {html.escape(v["phase"].replace("_", " ").title())}</span>'
            f"  </div>"
            f"</div>"
        )
    return "\n".join(parts)


def _build_legend_html() -> str:
    parts: list[str] = ['<div class="legend-grid">']
    for ntype, colors in _NODE_COLORS.items():
        label = ntype.replace("_", " ").title()
        bg = colors["background"]
        shape_name = _NODE_SHAPES.get(ntype, "dot")
        parts.append(
            f'<div class="legend-item">'
            f'  <span class="legend-swatch" style="background:{bg};'
            f'    border-radius:{"50%" if shape_name in ("dot", "ellipse") else "3px"}"></span>'
            f"  {html.escape(label)}"
            f"</div>"
        )
    parts.append("</div>")
    return "\n".join(parts)


_OWASP_DESCRIPTIONS: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Unbounded Consumption",
}


def _build_owasp_html(
    attack_results: list[dict[str, Any]],
    phases: list[dict[str, Any]],
) -> str:
    """Build an OWASP LLM Top 10 compliance summary table."""
    from collections import Counter

    findings: Counter[str] = Counter()
    tested: set[str] = set()

    # Gather from attack_results
    for ar in attack_results:
        for cat in ar.get("owasp_mapping", []):
            tested.add(cat)
            if ar.get("successful"):
                findings[cat] += 1

    # Gather from phase artifacts
    for p in phases:
        artifacts = p.get("artifacts", {})
        vuln_ids = set(p.get("vulnerabilities_found", []))
        for vid, art in artifacts.items():
            for cat in art.get("owasp_mapping", []):
                tested.add(cat)
                if vid in vuln_ids:
                    findings[cat] += 1

    if not tested:
        return '<p class="muted">No OWASP mapping data available.</p>'

    parts: list[str] = ['<table class="owasp-table">']
    parts.append(
        "<tr><th>Category</th><th>Description</th><th>Status</th><th>Findings</th></tr>"
    )
    for cat_id in ("LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
                    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"):
        desc = html.escape(_OWASP_DESCRIPTIONS.get(cat_id, ""))
        if cat_id in findings:
            count = findings[cat_id]
            status = '<span class="sev-badge sev-critical">FAIL</span>'
            finding_text = f"{count} vuln{'s' if count != 1 else ''}"
        elif cat_id in tested:
            status = '<span class="sev-badge sev-ok">PASS</span>'
            finding_text = "—"
        else:
            status = '<span class="sev-badge sev-untested">N/T</span>'
            finding_text = "—"
        parts.append(
            f"<tr><td><strong>{cat_id}</strong></td>"
            f"<td>{desc}</td><td>{status}</td><td>{finding_text}</td></tr>"
        )
    parts.append("</table>")
    return "\n".join(parts)


def _build_attack_log_html(attack_results: list[dict[str, Any]]) -> str:
    """Build collapsible attack-log cards grouped by phase."""
    if not attack_results:
        return '<p class="muted">No attack data recorded.</p>'

    # Group by phase
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for ar in attack_results:
        phase = ar.get("evidence", {}).get("phase", "unknown")
        by_phase.setdefault(phase, []).append(ar)

    parts: list[str] = []
    idx = 0
    for phase, results in by_phase.items():
        phase_label = phase.replace("_", " ").title()
        parts.append(f'<div class="log-phase-group">{html.escape(phase_label)}</div>')

        for ar in results:
            successful = ar.get("successful", False)
            name = ar.get("vector_name", ar.get("vector_id", "unknown"))
            severity = ar.get("severity", "unknown")
            category = ar.get("category", "unknown").replace("_", " ")
            prompt_used = ar.get("prompt_used") or ""
            agent_response = ar.get("agent_response") or ""
            evidence = ar.get("evidence", {})
            matched = evidence.get("matched_indicators", [])
            snippet = evidence.get("response_snippet", "")

            # Use snippet if full response is absent
            display_response = agent_response or snippet

            icon = "🔓" if successful else "🛡️"
            result_cls = "attack-success" if successful else "attack-blocked"
            result_label = "Exploited" if successful else "Blocked"

            sev = severity.lower()
            sev_cls = (
                "sev-critical"
                if sev in ("critical", "high")
                else "sev-medium"
                if sev == "medium"
                else "sev-low"
            )

            parts.append(
                f'<details class="attack-card {result_cls}">'
                f'<summary class="attack-summary">'
                f'  <span class="attack-icon">{icon}</span>'
                f'  <span class="attack-name">{html.escape(name)}</span>'
                f'  <span class="sev-badge {sev_cls}">{html.escape(severity)}</span>'
                f'  <span class="attack-result-badge {result_cls}">{result_label}</span>'
                f"</summary>"
                f'<div class="attack-body">'
            )

            parts.append(
                f'  <div class="attack-meta">'
                f"    <span>Category: {html.escape(category)}</span>"
                f"  </div>"
            )

            if prompt_used:
                esc_prompt = html.escape(prompt_used)
                parts.append(
                    f'  <div class="attack-section-label">Prompt Sent</div>'
                    f'  <pre class="attack-pre prompt-pre">{esc_prompt}</pre>'
                )

            if display_response:
                esc_resp = html.escape(display_response)
                parts.append(
                    f'  <div class="attack-section-label">Agent Response</div>'
                    f'  <pre class="attack-pre response-pre">{esc_resp}</pre>'
                )

            if matched:
                indicators = ", ".join(html.escape(str(m)) for m in matched)
                parts.append(
                    f'  <div class="attack-section-label">Matched Indicators</div>'
                    f'  <div class="attack-indicators">{indicators}</div>'
                )

            parts.append("</div></details>")
            idx += 1

    return "\n".join(parts)


# ── Full HTML template ─────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KOAN Report — {campaign_id}</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  :root {{
    --bg: #0f172a;
    --bg-card: #1e293b;
    --bg-hover: #334155;
    --text: #f8fafc;
    --muted: #94a3b8;
    --accent: #3b82f6;
    --danger: #ef4444;
    --safe: #10b981;
    --orange: #f59e0b;
    --purple: #8b5cf6;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    display: flex;
    height: 100vh;
    overflow: hidden;
  }}

  /* ── Sidebar ───────────────────────────────────────────────── */
  .sidebar {{
    width: 380px;
    min-width: 380px;
    background: var(--bg-card);
    border-right: 1px solid #334155;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #475569 transparent;
  }}
  .sidebar-header {{
    padding: 20px;
    border-bottom: 1px solid #334155;
  }}
  .sidebar-header h1 {{
    font-size: 1.3rem;
    font-weight: 700;
    margin-bottom: 4px;
  }}
  .sidebar-header .koan-brand {{
    color: var(--accent);
  }}
  .sidebar-header .subtitle {{
    color: var(--muted);
    font-size: 0.8rem;
  }}

  .section {{
    padding: 16px 20px;
    border-bottom: 1px solid #334155;
  }}
  .section-title {{
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin-bottom: 10px;
    font-weight: 600;
  }}

  /* Metric grid */
  .metric-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }}
  .metric {{
    background: var(--bg);
    padding: 10px;
    border-radius: 8px;
  }}
  .metric-value {{
    font-size: 1.4rem;
    font-weight: 700;
  }}
  .metric-label {{
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 2px;
  }}
  .metric-value.danger {{ color: var(--danger); }}
  .metric-value.safe {{ color: var(--safe); }}
  .metric-value.accent {{ color: var(--accent); }}
  .metric-value.orange {{ color: var(--orange); }}

  /* Trust gauge */
  .trust-bar {{
    width: 100%;
    height: 6px;
    background: #334155;
    border-radius: 3px;
    margin-top: 8px;
    overflow: hidden;
  }}
  .trust-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
  }}

  /* Phase cards */
  .phase-card {{
    background: var(--bg);
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 6px;
    border-left: 3px solid var(--safe);
  }}
  .phase-card.phase-danger {{
    border-left-color: var(--danger);
  }}
  .phase-header {{
    font-size: 0.85rem;
    font-weight: 600;
  }}
  .phase-meta {{
    display: flex;
    gap: 12px;
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 4px;
  }}

  /* Attack paths */
  .path-item {{
    background: var(--bg);
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 4px;
    font-size: 0.78rem;
    cursor: pointer;
    transition: background 0.15s;
    font-family: 'Fira Code', monospace, monospace;
    word-break: break-all;
  }}
  .path-item:hover {{
    background: var(--bg-hover);
  }}
  .path-item.active {{
    background: var(--bg-hover);
    box-shadow: inset 3px 0 0 var(--danger);
  }}
  .path-num {{
    color: var(--danger);
    font-weight: 700;
    margin-right: 4px;
  }}

  /* Vulnerabilities */
  .vuln-card {{
    background: var(--bg);
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 6px;
  }}
  .vuln-name {{
    font-weight: 600;
    font-size: 0.85rem;
  }}
  .vuln-meta {{
    display: flex;
    gap: 10px;
    align-items: center;
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 4px;
  }}
  .sev-badge {{
    padding: 1px 7px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.68rem;
    text-transform: uppercase;
  }}
  .sev-critical {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
  .sev-medium {{ background: rgba(245,158,11,0.2); color: #fcd34d; }}
  .sev-low {{ background: rgba(16,185,129,0.2); color: #6ee7b7; }}
  .sev-ok {{ background: rgba(16,185,129,0.2); color: #6ee7b7; }}
  .sev-untested {{ background: rgba(148,163,184,0.2); color: #94a3b8; }}

  /* OWASP table */
  .owasp-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
  }}
  .owasp-table th {{
    text-align: left;
    padding: 6px 8px;
    color: var(--muted);
    font-weight: 600;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #334155;
  }}
  .owasp-table td {{
    padding: 5px 8px;
    border-bottom: 1px solid rgba(51,65,85,0.5);
  }}

  /* Legend */
  .legend-grid {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .legend-item {{
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 0.75rem;
    color: var(--muted);
  }}
  .legend-swatch {{
    width: 12px;
    height: 12px;
    display: inline-block;
  }}

  .muted {{ color: var(--muted); font-size: 0.8rem; }}

  /* Attack log */
  .log-phase-group {{
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--purple);
    margin: 10px 0 6px;
    padding-bottom: 3px;
    border-bottom: 1px solid #334155;
  }}
  .attack-card {{
    background: var(--bg);
    border-radius: 8px;
    margin-bottom: 6px;
    border-left: 3px solid var(--safe);
    overflow: hidden;
  }}
  .attack-card.attack-success {{
    border-left-color: var(--danger);
  }}
  .attack-summary {{
    padding: 8px 10px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.8rem;
    list-style: none;
  }}
  .attack-summary::-webkit-details-marker {{ display: none; }}
  .attack-summary::before {{
    content: '▸';
    color: var(--muted);
    font-size: 0.7rem;
    transition: transform 0.15s;
  }}
  details[open] > .attack-summary::before {{
    transform: rotate(90deg);
  }}
  .attack-icon {{ font-size: 0.9rem; }}
  .attack-name {{ font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .attack-result-badge {{
    font-size: 0.62rem;
    padding: 1px 6px;
    border-radius: 3px;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .attack-result-badge.attack-success {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
  .attack-result-badge.attack-blocked {{ background: rgba(16,185,129,0.15); color: #6ee7b7; }}
  .attack-body {{
    padding: 4px 10px 10px;
  }}
  .attack-meta {{
    font-size: 0.72rem;
    color: var(--muted);
    margin-bottom: 6px;
  }}
  .attack-section-label {{
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 8px 0 3px;
    font-weight: 600;
  }}
  .attack-pre {{
    font-family: 'Fira Code', monospace;
    font-size: 0.72rem;
    padding: 8px;
    border-radius: 6px;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 200px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #475569 transparent;
    line-height: 1.45;
  }}
  .prompt-pre {{
    background: rgba(59,130,246,0.08);
    border: 1px solid rgba(59,130,246,0.15);
    color: #93c5fd;
  }}
  .response-pre {{
    background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.15);
    color: #fcd34d;
  }}
  .attack-indicators {{
    font-family: 'Fira Code', monospace;
    font-size: 0.72rem;
    color: var(--danger);
    padding: 4px 0;
  }}

  /* ── Graph container ───────────────────────────────────────── */
  .graph-container {{
    flex: 1;
    position: relative;
  }}
  #graph-canvas {{
    width: 100%;
    height: 100%;
  }}

  /* Node detail overlay */
  .node-detail {{
    position: absolute;
    top: 16px;
    right: 16px;
    width: 300px;
    background: var(--bg-card);
    border: 1px solid #475569;
    border-radius: 10px;
    padding: 16px;
    display: none;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    z-index: 10;
  }}
  .node-detail.visible {{
    display: block;
  }}
  .node-detail h3 {{
    font-size: 0.95rem;
    margin-bottom: 8px;
    word-break: break-all;
  }}
  .node-detail .detail-row {{
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 3px;
  }}
  .node-detail .detail-row b {{
    color: var(--text);
  }}
  .close-btn {{
    position: absolute;
    top: 8px;
    right: 12px;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 1.1rem;
  }}
  .close-btn:hover {{ color: var(--text); }}

  /* Controls bar */
  .graph-controls {{
    position: absolute;
    bottom: 16px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    gap: 8px;
    z-index: 10;
  }}
  .graph-controls button {{
    background: var(--bg-card);
    border: 1px solid #475569;
    color: var(--text);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.78rem;
    transition: background 0.15s;
  }}
  .graph-controls button:hover {{
    background: var(--bg-hover);
  }}
  .graph-controls button.active {{
    background: var(--accent);
    border-color: var(--accent);
  }}
</style>
</head>
<body>

<!-- ─── Sidebar ──────────────────────────────────────────────────── -->
<aside class="sidebar">
  <div class="sidebar-header">
    <h1><span class="koan-brand">KOAN</span> Security Report</h1>
    <div class="subtitle">{campaign_id} — {target_agent}</div>
  </div>

  <!-- Summary metrics -->
  <div class="section">
    <div class="section-title">Campaign Summary</div>
    <div class="metric-grid">
      <div class="metric">
        <div class="metric-value {success_class}">{success_label}</div>
        <div class="metric-label">Result</div>
      </div>
      <div class="metric">
        <div class="metric-value danger">{total_vulns}</div>
        <div class="metric-label">Vulnerabilities</div>
      </div>
      <div class="metric">
        <div class="metric-value orange">{num_paths}</div>
        <div class="metric-label">Attack Paths</div>
      </div>
      <div class="metric">
        <div class="metric-value accent">{trust_score}</div>
        <div class="metric-label">Trust Score</div>
      </div>
    </div>
    <div class="trust-bar">
      <div class="trust-fill" style="width:{trust_pct}%;background:linear-gradient(90deg,var(--safe),var(--orange),var(--danger));"></div>
    </div>
  </div>

  <!-- Graph stats -->
  <div class="section">
    <div class="section-title">Knowledge Graph</div>
    <div class="metric-grid">
      <div class="metric">
        <div class="metric-value accent">{total_nodes}</div>
        <div class="metric-label">Nodes</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color:var(--purple)">{total_edges}</div>
        <div class="metric-label">Edges</div>
      </div>
    </div>
    {legend_html}
  </div>

  <!-- Token Usage -->
  <div class="section">
    <div class="section-title">Token Usage</div>
    <div class="metric-grid">
      <div class="metric">
        <div class="metric-value accent">{prompt_tokens}</div>
        <div class="metric-label">Prompt Tokens</div>
      </div>
      <div class="metric">
        <div class="metric-value accent">{completion_tokens}</div>
        <div class="metric-label">Completion Tokens</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color:var(--orange)">{total_tokens}</div>
        <div class="metric-label">Total Tokens</div>
      </div>
      <div class="metric">
        <div class="metric-value" style="color:var(--purple)">{coverage_level}</div>
        <div class="metric-label">Coverage</div>
      </div>
    </div>
  </div>

  <!-- Phases -->
  <div class="section">
    <div class="section-title">Phase Timeline</div>
    {phases_html}
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-title">Vulnerabilities</div>
    {vulns_html}
  </div>

  <!-- OWASP LLM Top 10 Compliance -->
  <div class="section">
    <div class="section-title">OWASP LLM Top 10</div>
    {owasp_html}
  </div>

  <!-- Attack Paths -->
  <div class="section">
    <div class="section-title">Critical Attack Paths</div>
    {paths_html}
  </div>

  <!-- Attack Log -->
  <div class="section">
    <div class="section-title">Attack Log</div>
    {attack_log_html}
  </div>
</aside>

<!-- ─── Graph ────────────────────────────────────────────────────── -->
<main class="graph-container">
  <div id="graph-canvas"></div>

  <!-- Node detail overlay -->
  <div class="node-detail" id="nodeDetail">
    <button class="close-btn" onclick="closeDetail()">✕</button>
    <h3 id="detailTitle"></h3>
    <div id="detailBody"></div>
  </div>

  <!-- Controls -->
  <div class="graph-controls">
    <button onclick="fitGraph()">Fit View</button>
    <button onclick="togglePhysics(this)" id="physicsBtn">Pause Physics</button>
    <button onclick="resetHighlight()">Clear Highlight</button>
  </div>
</main>

<script>
// ── Data ───────────────────────────────────────────────────────────
const rawNodes = {vis_nodes_json};
const rawEdges = {vis_edges_json};
const criticalPaths = {critical_paths_json};

// ── Initialise vis-network ────────────────────────────────────────
const nodes = new vis.DataSet(rawNodes);
const edges = new vis.DataSet(rawEdges);

const container = document.getElementById('graph-canvas');
const data = {{ nodes: nodes, edges: edges }};

const options = {{
  physics: {{
    enabled: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {{
      gravitationalConstant: -40,
      centralGravity: 0.005,
      springLength: 120,
      springConstant: 0.06,
      damping: 0.4,
    }},
    stabilization: {{ iterations: 200, fit: true }},
  }},
  interaction: {{
    hover: true,
    tooltipDelay: 200,
    zoomView: true,
    dragView: true,
    navigationButtons: false,
  }},
  edges: {{
    font: {{ size: 10 }},
  }},
  layout: {{
    improvedLayout: true,
  }},
}};

const network = new vis.Network(container, data, options);

// ── Click handler — show node detail ──────────────────────────────
network.on('click', function(params) {{
  if (params.nodes.length > 0) {{
    const nodeId = params.nodes[0];
    const node = nodes.get(nodeId);
    showDetail(node);
  }} else {{
    closeDetail();
  }}
}});

function showDetail(node) {{
  const panel = document.getElementById('nodeDetail');
  const title = document.getElementById('detailTitle');
  const body  = document.getElementById('detailBody');
  title.textContent = node.label;

  let html = '';
  html += '<div class="detail-row"><b>ID:</b> ' + escHtml(node.id) + '</div>';
  html += '<div class="detail-row"><b>Type:</b> ' + escHtml(node.nodeType || 'unknown') + '</div>';

  // Find connected edges
  const connected = edges.get({{
    filter: e => e.from === node.id || e.to === node.id
  }});
  if (connected.length) {{
    html += '<div class="detail-row" style="margin-top:8px"><b>Connections:</b></div>';
    connected.forEach(e => {{
      const dir = e.from === node.id ? '→' : '←';
      const other = e.from === node.id ? e.to : e.from;
      html += '<div class="detail-row">&nbsp;&nbsp;' + dir + ' ' + escHtml(other) + ' <span style="color:#64748b">(' + escHtml(e.label || '') + ')</span></div>';
    }});
  }}
  body.innerHTML = html;
  panel.classList.add('visible');
}}

function closeDetail() {{
  document.getElementById('nodeDetail').classList.remove('visible');
}}

// ── Attack-path highlighting ──────────────────────────────────────
let activePathIndex = -1;

function highlightPath(index) {{
  resetHighlight();
  if (index >= criticalPaths.length) return;
  activePathIndex = index;

  const path = criticalPaths[index];
  const pathSet = new Set(path);

  // Dim all nodes & edges
  nodes.update(rawNodes.map(n => ({{
    id: n.id,
    opacity: pathSet.has(n.id) ? 1 : 0.15,
    font: {{ ...n.font, color: pathSet.has(n.id) ? '#f8fafc' : '#334155' }},
  }})));

  // Highlight edges that connect consecutive path nodes
  const pathEdgeIds = new Set();
  for (let i = 0; i < path.length - 1; i++) {{
    edges.get({{ filter: e => e.from === path[i] && e.to === path[i + 1] }})
      .forEach(e => pathEdgeIds.add(e.id));
  }}

  edges.update(rawEdges.map(e => ({{
    id: e.id,
    color: pathEdgeIds.has(e.id)
      ? {{ color: '#ef4444', opacity: 1 }}
      : {{ color: '#334155', opacity: 0.1 }},
    width: pathEdgeIds.has(e.id) ? 3.5 : 1,
    font: {{ ...e.font, color: pathEdgeIds.has(e.id) ? '#fca5a5' : 'transparent' }},
  }})));

  // Mark active path card
  document.querySelectorAll('.path-item').forEach(el => el.classList.remove('active'));
  const el = document.querySelector('[data-path-index="' + index + '"]');
  if (el) el.classList.add('active');

  // Zoom to the path nodes
  network.fit({{ nodes: path, animation: {{ duration: 400, easingFunction: 'easeInOutQuad' }} }});
}}

function resetHighlight() {{
  activePathIndex = -1;
  nodes.update(rawNodes.map(n => ({{
    id: n.id,
    opacity: 1,
    font: n.font,
  }})));
  edges.update(rawEdges.map(e => ({{
    id: e.id,
    color: e.color,
    width: e.width,
    font: e.font,
  }})));
  document.querySelectorAll('.path-item').forEach(el => el.classList.remove('active'));
}}

// ── Toolbar ───────────────────────────────────────────────────────
function fitGraph() {{
  network.fit({{ animation: {{ duration: 400, easingFunction: 'easeInOutQuad' }} }});
}}

let physicsEnabled = true;
function togglePhysics(btn) {{
  physicsEnabled = !physicsEnabled;
  network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
  btn.textContent = physicsEnabled ? 'Pause Physics' : 'Resume Physics';
  btn.classList.toggle('active', !physicsEnabled);
}}

// ── Helpers ───────────────────────────────────────────────────────
function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}
</script>
</body>
</html>
"""
