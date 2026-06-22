# Data Model: Interactive Knowledge Graph Visualization

**Feature**: 026-interactive-knowledge-graph
**Date**: 2026-06-22

This feature is primarily presentational, but it (a) enriches the exported graph state, (b) introduces a canonical style spec entity, and (c) persists per-phase graph snapshots. Below are the affected/added entities.

## 1. Exported graph node (enriched) — `application/knowledge_graph`

`export_state()` already emits `{"id": ..., **node_attrs}`. This feature **adds** computed/normalized fields when present:

| Field | Type | Source | Used by | Notes |
|---|---|---|---|---|
| `id` | str | existing | both surfaces | node identity / cross-link key |
| `node_type` | str | existing | styling, filters | one of: agent, agent_state, capability, tool, data_source, vulnerability, phase |
| `name` | str | existing (where set) | label | falls back to `id` |
| `centrality` | float (0–1) | **NEW** — normalized betweenness | node size encoding | 0 when graph too small / not computable |
| `severity` | str \| null | existing (vulnerabilities) | color/border | e.g. critical/high/medium/low/info |
| `dangerous` | bool | existing (capabilities) | danger marker | only on capability nodes |
| `phase` | str \| null | **NEW** — derived earliest discovering phase | hierarchical layout band | null → "unassigned" band |
| `risk_score` | float \| null | existing (where set) | optional encoding | |

**Validation/derivation rules**:
- `centrality` is min-max normalized across the graph's nodes; absent → default size.
- `phase` derived from `discovered_in`/`executed_in` edges to a `phase` node; first/earliest wins; otherwise null.
- No node is dropped for missing fields.

## 2. Exported graph edge — `application/knowledge_graph`

Unchanged shape; styling now driven by the shared spec.

| Field | Type | Used by |
|---|---|---|
| `source` | str | edge identity |
| `target` | str | edge identity |
| `edge_type` | str | styling, filters, semantic emphasis |
| `risk_score` | float \| null | attack-edge emphasis |
| `chain_position` | int \| null | attack-chain ordering |

`edge_type` ∈ { uses_tool, accesses_data, trusts, enables, can_chain_to, discovered_in, exploits, leads_to, delegates_to, shares_context, trust_boundary }. Attack-relevant types emphasized: `exploits`, `can_chain_to`, `leads_to`.

## 3. Graph style/mapping spec (canonical JSON) — `interfaces/graph_style`

A single committed JSON file validated by a Pydantic model. The single source of truth for both surfaces.

| Field | Type | Description |
|---|---|---|
| `version` | str | spec version for parity assertions |
| `node_types` | map<str, NodeStyle> | per node_type: `color`, `shape`, `base_size` |
| `edge_types` | map<str, EdgeStyle> | per edge_type: `color`, `dashes` (bool/list), `width`, `arrow` |
| `severity_ramp` | map<str, str> | severity → color (critical…info) |
| `danger_marker` | DangerMarker | border color/width + shadow for dangerous nodes |
| `phase_order` | list<str> | fixed methodology order for hierarchical bands |
| `size_encoding` | SizeEncoding | `min_size`, `max_size` for centrality→size mapping |
| `attack_edge_types` | list<str> | edge types to emphasize (exploits, can_chain_to, leads_to) |
| `thresholds` | Thresholds | `large_graph_node_threshold` (default 200), `auto_cluster` (bool) |

**Validation rules** (Pydantic):
- Every node_type/edge_type key must be a known type string.
- `phase_order` non-empty, unique entries.
- `min_size < max_size`; sizes > 0.
- Colors are valid hex/rgba strings.
- A **parity test** asserts the JSON validates and matches the TS-side contract.

## 4. PhaseResultRow (persistence change) — `interfaces/web/models.py`

Add one nullable column to the existing `phase_results` table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `graph_state_json` | JSONB | yes | **NEW** — per-phase snapshot from `PhaseResult.graph_state` (`export_state()` output). Null for rows created before this migration. |

Existing columns unchanged (`id, run_id, phase, phase_index, success, trust_score, duration_seconds, token_usage_json, vulnerabilities_found, discovered_capabilities, error`).

**State/ordering**: per-phase states are ordered by `phase_index`; the scrubber walks them ascending. Each successive snapshot is a superset of the previous (graph only grows), satisfying SC-007.

## 5. API response additions — `interfaces/web/schemas.py`

`PhaseResultSchema` gains:

| Field | Type | Notes |
|---|---|---|
| `graph_state` | dict \| null | the per-phase snapshot; null when not persisted (older runs) |

`RunDetail.graph_state_json` (final state) is unchanged and remains the fallback for the scrubber.

## 6. UI types — `ui/src/types/index.ts`

`GraphNode` / `GraphEdge` / `GraphState` gain typed optional fields mirroring the enriched export (`centrality?`, `severity?`, `phase?`, `dangerous?`, `risk_score?`, `chain_position?`). `PhaseResult` (UI) gains `graph_state?: GraphState | null`.

## Relationships

```
Run 1───* PhaseResultRow            (existing FK; each row now carries an optional per-phase graph snapshot)
PhaseResultRow.graph_state_json  ≈  GraphState (export_state output)
GraphNode(id) ──cross-link──> Finding(vector_id|vulnerability id) ──> ComplianceMapping(owasp/atlas)
Graph style spec (JSON) ──consumed by──> { Python report, TS UI }   (single source of truth)
```
