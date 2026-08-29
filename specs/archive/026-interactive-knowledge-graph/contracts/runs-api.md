# Contract: Runs API — per-phase graph snapshots

**Feature**: 026-interactive-knowledge-graph (P3)

## Endpoint (unchanged path, extended response)

`GET /api/runs/{run_id}` → `RunDetail`

### Change

`RunDetail.phase_results[]` (`PhaseResultSchema`) gains an optional `graph_state` field carrying the per-phase knowledge-graph snapshot. `RunDetail.graph_state_json` (the final-state graph) is unchanged.

### Response shape (relevant excerpt)

```jsonc
{
  "id": "…uuid…",
  "graph_state_json": { /* final-state GraphState — unchanged */ },
  "phase_results": [
    {
      "phase": "reconnaissance",
      "phase_index": 0,
      "success": true,
      "trust_score": 0.8,
      "duration_seconds": 12.3,
      "vulnerabilities_found": ["…"],
      "discovered_capabilities": ["…"],
      "graph_state": {                 // NEW — may be null for older runs
        "nodes": [ { "id": "…", "node_type": "…", "centrality": 0.42,
                     "severity": "high", "phase": "reconnaissance", "dangerous": false } ],
        "edges": [ { "source": "…", "target": "…", "edge_type": "exploits" } ],
        "campaign_start": "…iso…",
        "campaign_duration_seconds": 12.3,
        "stats": { "total_nodes": 10, "total_edges": 8, "density": 0.1,
                   "node_types": { "tool": 3 } }
      }
    }
  ]
}
```

### Contract rules

- `graph_state` is **nullable**. For runs created before migration `003_phase_graph_state`, it is `null`; clients MUST fall back to `graph_state_json` (final state) for the scrubber.
- When present, each phase's `graph_state` is a valid `export_state()` payload and is a **superset** of the previous phase's snapshot (nodes/edges only added).
- Enriched node fields (`centrality`, `phase`, `severity`, `dangerous`) are optional per node and absent when not computable; clients MUST apply default encoding.
- No new endpoint is added; no breaking change to existing fields.

### Tests (integration)

1. Run with N phases → response has N `phase_results`, each with a non-null `graph_state` whose node count is monotonic non-decreasing by `phase_index`.
2. Legacy run (no per-phase persistence) → `graph_state` is `null` on each phase; `graph_state_json` still present.
3. Final phase `graph_state` equals `graph_state_json`.
