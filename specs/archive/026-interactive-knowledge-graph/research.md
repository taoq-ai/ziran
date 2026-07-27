# Research: Interactive Knowledge Graph Visualization

**Feature**: 026-interactive-knowledge-graph
**Date**: 2026-06-22

This document records the key technical decisions resolved during planning, grounded in the current codebase.

## R1 — Single source of truth for styling/mapping across two languages (P4)

**Decision**: Introduce a **canonical, language-neutral JSON spec** (`ziran/interfaces/graph_style/graph_style.json`) describing node-type styling (color/shape/size), edge-type styling (color/dash/width), the severity color ramp, the dangerous-capability marker, the fixed phase order, and tunable thresholds (large-graph node count, auto-cluster trigger). Both surfaces consume it:
- **Python report**: a Pydantic-validated loader (`graph_style/spec.py`) reads the JSON; `graph_state_to_vis` and the report template are driven by it.
- **TypeScript UI**: imports the same JSON file via a Vite path alias (`@graphstyle`) and wraps it in typed accessors (`graphStyle.ts`).
- A **parity test** (pytest) asserts the JSON validates against the Pydantic model and that the documented TS contract (a small generated/committed type) matches the JSON keys, so drift fails CI.

**Rationale**: The report is a self-contained Python-generated HTML file (f-string template, CDN vis-network) and the UI is a separately-built Vite bundle — they cannot share runtime code. A static JSON data file is the only artifact both build systems can consume without coupling. It also satisfies the constitution's data-driven styling preference (Principle V) and removes the current duplicated `_NODE_COLORS`/`NODE_COLORS` constants.

**Alternatives considered**:
- *Backend computes vis-ready payload, both consume it*: rejected — the CLI report runs offline with no API, so it can't fetch a server-rendered payload; and it would still need the mapping logic in Python anyway.
- *Define spec in TS, generate Python from it*: rejected — adds a JS build step to the Python package's test/release path.
- *Keep two copies, add a lint check*: rejected — does not remove duplication; spec explicitly asks for one source of truth.

**Note on mapping logic**: The imperative `graphState → vis nodes/edges` transform is necessarily mirrored in Python and TS, but it is thin and reads *all* tunable values from the shared JSON. Both implementations are unit-tested against the same fixture to keep them aligned.

## R2 — Hierarchical-by-phase layout (P1)

**Decision**: Port the band logic from `ziran/interfaces/cli/visualizations/__init__.py::_hierarchical_phase_layout` into the shared concept: assign each node to the earliest phase it was discovered in (via `discovered_in`/`executed_in` edges to a `phase` node), order phases by the fixed methodology sequence, and place nodes in left-to-right columns. In the UI, use vis-network's `layout.hierarchical` (direction LR) seeded by computed `level` per node; in the report, the same. Nodes with no phase attribution go to an "unassigned" band.

**Rationale**: The logic already exists and is proven for the Plotly report; reusing it (rather than inventing a layout) satisfies Simplicity. vis-network supports hierarchical layout natively, so no library change is needed.

**Phase order** (canonical, in the JSON spec): `reconnaissance, trust_building, capability_mapping, vulnerability_discovery, exploitation_setup, execution, persistence, exfiltration`.

**Alternatives considered**: Custom physics tuning to fake bands — rejected as fragile. New layout library (cytoscape/sigma) — rejected per issue recommendation to stay on vis-network.

## R3 — Encoding importance: centrality must be attached to nodes (P1)

**Decision**: Enrich `AttackKnowledgeGraph.export_state()` to attach a normalized `centrality` value (betweenness, reusing `get_critical_nodes`/the existing betweenness computation) to every node in the exported state. Node size is then `f(centrality)` clamped to a min/max from the spec. Severity color/border reads the existing `severity` attribute; dangerous capabilities read the existing `dangerous` flag.

**Rationale**: Betweenness is computed today but **not present on exported nodes** (`export_state` emits raw node attrs only). Without attaching it, the UI/report cannot size by centrality. Computing once on the backend keeps both surfaces consistent and avoids shipping the whole graph to the client for recomputation. Normalization (0–1) makes the spec's size mapping deterministic across runs of different scale.

**Alternatives considered**: Compute centrality client-side in JS — rejected (recompute cost, divergence from report, no JS graph-analytics dep). Use degree instead of betweenness — rejected (issue explicitly says betweenness/chokepoints).

## R4 — Per-phase snapshot persistence (P3)

**Decision**: Add a nullable `graph_state_json` JSONB column to the `phase_results` table via a new Alembic migration (`003_phase_graph_state.py`, following the `NNN_description.py` convention after `002_findings_schema.py`). Persist `PhaseResult.graph_state` (already populated in memory via `export_state()`) for each phase in `run_manager` when inserting `PhaseResultRow`. Expose it through `PhaseResultSchema.graph_state` and the `GET /api/runs/{id}` response. The UI builds the scrubber from the ordered per-phase states; when a phase's `graph_state` is null (older runs), the scrubber falls back to the run's final `graph_state_json`.

**Rationale**: The data already exists in memory (`PhaseResult.graph_state`) and is simply discarded except for the final phase. Persisting per-phase is the minimal change that unlocks temporal scrubbing. JSONB matches the existing `Run.graph_state_json` pattern. Nullable column + fallback preserves backward compatibility with existing rows.

**Storage cost note**: per-phase snapshots duplicate node/edge data across phases. Acceptable for the expected scale (≤8 phases, a few thousand nodes); if it becomes a concern later, a delta encoding is a future optimization (explicitly out of scope now — YAGNI).

**Alternatives considered**: Recompute per-phase states from an event log — rejected (no such log persisted). Separate snapshots table — rejected as over-structured for a 1:1-with-phase relationship.

## R5 — Clustering & large-graph UX (P2/P3)

**Decision**: Use vis-network's `cluster()` / `openCluster()` API to collapse/expand by phase or by node type into labeled super-nodes (`label = "{group} (N)"`). Above the spec's `largeGraphNodeThreshold` (default 200, matching today's physics cutoff), auto-cluster by phase on first render and disable physics. Provide explicit expand/collapse controls.

**Rationale**: vis-network clustering is built-in and the existing component already disables physics above 200 nodes, so the threshold is a natural reuse point. Keeps large graphs navigable (SC-004).

**Report note**: the self-contained report includes the same clustering JS; it ships inline so it works offline.

## R6 — Cross-linking node ↔ finding / attack-log / OWASP-ATLAS (P2)

**Decision**: Link via existing identifiers. A vulnerability node's `id` corresponds to a finding discovered from an attack result; findings carry `vector_id`, `vector_name`, `category`, and `owasp_category`, and attack results carry `vector_id`, `owasp_mapping`, `atlas_mapping`. The mapping from a graph node to a finding/attack-log entry is resolved by matching on these identifiers (vector_id / vulnerability id / capability id). In the UI, clicking a node scrolls to / opens the corresponding finding row and attack-log card; activating a finding row focuses the node. The report (offline) provides anchor-link cross-navigation within the single HTML document.

**Rationale**: All identifiers already exist; no schema change needed for cross-linking. The UI fetches findings/compliance via existing `findings.ts`/`compliance.ts` hooks. The report already renders findings, attack log, OWASP, and ATLAS sections — they just need anchor IDs wired to node clicks.

**Alternatives considered**: Add explicit node→finding foreign keys — rejected (the vector_id/id correspondence already exists; adding FKs is unnecessary coupling).

## R7 — Multi-agent topology (P2)

**Decision**: Render `delegates_to`, `trust_boundary`, and `shares_context` edges with distinct styles from the shared spec, and group nodes by their owning `agent` so agent clusters are visually separable (reuse the clustering mechanism, clustered by agent). Absent in single-agent runs — no special-casing needed since those edge types simply won't be present.

**Rationale**: These edge types already exist in the model and just need styling + grouping; the spec-driven approach means adding them is a data change plus a grouping option, not new infrastructure.

## R8 — Frontend testing strategy

**Decision**: Add **Vitest** to the UI for unit-testing the pure modules (`graphMapping.ts`, `layouts.ts`, `graphStyle.ts`) against shared fixtures, and use the existing **Playwright** E2E setup for the user-story acceptance flows (layout toggle, filter, walker, scrubber, cross-link). Keep all DOM/vis-network-heavy logic thin so the bulk of logic is covered by fast unit tests.

**Rationale**: The UI currently has only Playwright E2E and no component/unit framework. The mapping/layout/style logic is pure and high-value to test in isolation; Vitest is the standard Vite-native choice and low-risk to add. The constitution's 85% coverage gate targets `ziran/` (Python); frontend tests are additive quality, not gated, so Vitest is justified but scoped to the pure logic.

**Alternatives considered**: Jest — rejected (Vite-native Vitest integrates with the existing build). No frontend unit tests — rejected (the mapping logic is the riskiest part of P4 parity).

## R9 — Stay on vis-network (library decision)

**Decision**: Keep vis-network on both surfaces (UI v10.0.2, report CDN — bump report CDN to a 10.x line to match the UI and the shared spec assumptions). No alternative library.

**Rationale**: The issue's own recommendation; vis-network already provides hierarchical layout and clustering, which cover the P1/P2 needs without a migration. Aligning the report's CDN version with the UI avoids subtle behavioral drift.
