# Contract: Shared graph style/mapping spec

**Feature**: 026-interactive-knowledge-graph (P4)

The canonical JSON file `ziran/interfaces/graph_style/graph_style.json` is the single source of truth consumed by both the Python HTML report and the TypeScript web UI.

## JSON schema (informal)

```jsonc
{
  "version": "1",
  "node_types": {
    "vulnerability": { "color": "#ef4444", "border": "#b91c1c", "shape": "diamond", "base_size": 22 },
    "tool":          { "color": "#10b981", "border": "#047857", "shape": "square",  "base_size": 18 }
    // …all 7 node types (each requires color, border, shape, base_size)
  },
  "edge_types": {
    "exploits":     { "color": "#ef4444", "dashes": [5,5], "width": 2, "arrow": true },
    "can_chain_to": { "color": "#f59e0b", "dashes": [2,2], "width": 2, "arrow": true }
    // …all 11 edge types
  },
  "severity_ramp": {
    "critical": "#dc2626", "high": "#ef4444", "medium": "#f59e0b",
    "low": "#eab308", "info": "#6b7280"
  },
  "danger_marker": { "border_color": "#ef4444", "border_width": 3,
                     "shadow_color": "rgba(239,68,68,0.5)", "shadow_size": 12 },
  "phase_order": ["reconnaissance","trust_building","capability_mapping",
                  "vulnerability_discovery","exploitation_setup","execution",
                  "persistence","exfiltration"],
  "size_encoding": { "min_size": 12, "max_size": 40 },
  "attack_edge_types": ["exploits","can_chain_to","leads_to"],
  "thresholds": { "large_graph_node_threshold": 200, "auto_cluster": true }
}
```

## Contract rules

- **Single source of truth**: changing any value here MUST change both surfaces with no surface-specific edits (FR-028/029).
- **Validation**: the Python loader (`graph_style/spec.py`) validates the JSON against a Pydantic model on load; invalid spec → fail fast with a clear error.
- **Parity**: a pytest test asserts (a) the JSON loads/validates, and (b) the set of node_type/edge_type keys equals the known type enums, and (c) the TS contract version matches `version`.
- **Self-contained report**: the report embeds the resolved styling inline (no runtime fetch of the JSON), but is generated from the same file (FR-030).
- **Mapping function** (`graph_state_to_vis` / `graphMapping.ts`) reads ALL tunable values from this spec — no hard-coded colors/sizes/thresholds remain in either surface.

## Tests

- Python unit: load + validate spec; `graph_state_to_vis(fixture)` produces vis nodes/edges whose colors/shapes/sizes come from the spec; dangerous node gets danger marker; size scales with `centrality`.
- TS (Vitest) unit: `graphMapping(fixture)` produces matching vis config from the same fixture + same JSON.
- Parity (pytest): node/edge type key sets and version match expectations.
