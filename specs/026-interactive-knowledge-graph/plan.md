# Implementation Plan: Interactive Knowledge Graph Visualization

**Branch**: `026-interactive-knowledge-graph` | **Date**: 2026-06-22 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/026-interactive-knowledge-graph/spec.md`

## Summary

Make the knowledge graph **structured, weighted, interactive, temporal, and consistent across both rendering surfaces** (the React web UI and the self-contained HTML CLI report). The current graph collapses a rich NetworkX model (7 node types, 11 edge types, centrality, attack paths, multi-agent trust) into a flat force-directed blob on both surfaces, with styling/mapping logic duplicated and drifting.

The technical approach:

1. **Shared style/mapping spec (P4, enabling refactor)** — Extract a single canonical, language-neutral JSON specification of node/edge styling, severity ramps, phase ordering, and thresholds. Python (report) and TypeScript (UI) both consume it; a parity test prevents drift. This lands first so every later visual feature is implemented against one source of truth.
2. **Structure + encoding + filters (P1, MVP)** — Add a hierarchical-by-phase layout (porting the band logic from the Plotly visualizer), enrich `export_state()` to attach per-node betweenness centrality so node size can encode importance, encode severity via color/border, mark dangerous capabilities, and turn the legend into type/edge/severity filter controls.
3. **Drill-down + investigation (P2)** — vis-network clustering (collapse/expand by phase or type, auto-cluster above a node threshold), an attack-chain walker over discovered paths, node↔finding/attack-log/OWASP-ATLAS cross-linking, and distinct rendering for multi-agent delegation/trust-boundary/context-sharing.
4. **Temporal + polish (P3)** — Persist per-phase graph snapshots (new `phase_results.graph_state_json` column + run_manager write + API exposure), add a phase scrubber, emphasize attack-relevant edges, and add empty/large-graph UX. Older runs without per-phase data fall back to final-state-only.

Delivery is phased into reviewable PRs against `develop`: **PR1 = P4 + P1**, **PR2 = P2**, **PR3 = P3**. Stay on vis-network (already supports the hierarchical layout and clustering we need).

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11/3.12/3.13) backend; TypeScript 5.x / React 18 frontend.
**Primary Dependencies**: Backend — FastAPI, SQLAlchemy 2.0 (async), Alembic, asyncpg, Pydantic v2, NetworkX, mdutils/f-string HTML report. Frontend — React 18, Vite, TanStack Query v5, vis-network v10.0.2 + vis-data v8, Tailwind/shadcn. Report — vis-network via CDN (currently v9.1.9). No new runtime dependencies anticipated (vis-network clustering + hierarchical layout already available).
**Storage**: PostgreSQL via asyncpg (`ZIRAN_DATABASE_URL`). New: `graph_state_json` JSONB column on `phase_results`.
**Testing**: Backend — pytest (`@pytest.mark.unit` / `@pytest.mark.integration`), mypy strict, ruff. Frontend — Playwright E2E (existing); add Vitest for unit-testing the shared graph mapping/style pure functions.
**Target Platform**: Linux server (API) + modern browsers (UI) + standalone HTML file (report, no backend/network access beyond the vis-network CDN).
**Project Type**: Web application (FastAPI backend + React frontend) plus a CLI report generator.
**Performance Goals**: Graph remains interactive; above a large-graph threshold (default 200 nodes, configurable in the shared spec) physics is disabled and auto-clustering applies so the view stays responsive.
**Constraints**: HTML report MUST remain self-contained (no live backend). Shared spec MUST be the single source of truth for styling/mapping. Hexagonal layering preserved. mypy strict, ruff clean, Python coverage >= 85%.
**Scale/Scope**: Graphs from tens to a few thousand nodes; up to 8 campaign phases; single- and multi-agent runs.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Hexagonal Architecture** — PASS. Backend changes stay in their layers: per-phase persistence is an `interfaces/web` concern (models, migration, run_manager service, route, schema); the graph style spec and `graph_state_to_vis` mapping are presentation concerns living under `interfaces/` (CLI report + a canonical spec file consumed by both surfaces). The centrality enrichment on `export_state()` is in `application/knowledge_graph` (it already owns analytics). No domain dependency on outer layers is introduced.
- **II. Type Safety** — PASS. New Python code (style-spec loader, API schema fields, run_manager change) is fully typed with Pydantic models; mypy strict must pass. The canonical style spec is validated by a Pydantic model. TS additions are typed.
- **III. Test Coverage** — PASS (with plan). Unit tests for: centrality enrichment in `export_state()`, the style-spec loader + parity check, `graph_state_to_vis` mapping. Integration tests for: per-phase persistence round-trip (run_manager → DB → API) and the API contract. Frontend: Vitest unit tests for the shared mapping/layout pure functions; Playwright E2E for the user-story flows. Python coverage stays >= 85%.
- **IV. Async-First** — PASS. New API surface reuses existing async route patterns; DB access via async SQLAlchemy. No new sync I/O.
- **V. Extensibility via Adapters** — PASS. The knowledge graph (NetworkX MultiDiGraph) remains the single source of truth during campaigns; we only enrich its export and persist additional snapshots. Styling is data-driven via the JSON spec, not hard-coded per surface.
- **VI. Simplicity** — PASS. The single canonical JSON spec replaces two drifting copies (net reduction). Reuse the existing Plotly band logic rather than inventing a new layout. No premature abstraction: the spec carries only values both surfaces actually consume.

**Result**: PASS. No violations; Complexity Tracking not required.

## Project Structure

### Documentation (this feature)

```text
specs/026-interactive-knowledge-graph/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (API + style-spec schema)
│   ├── graph-style-spec.md
│   └── runs-api.md
├── checklists/
│   └── requirements.md  # from /speckit.specify
└── tasks.md             # /speckit.tasks output (NOT created here)
```

### Source Code (repository root)

```text
ziran/
├── application/
│   └── knowledge_graph/
│       └── graph.py                      # export_state(): attach per-node centrality (P1)
├── interfaces/
│   ├── graph_style/                       # NEW — shared, surface-agnostic style/mapping (P4)
│   │   ├── __init__.py
│   │   ├── spec.py                        # Pydantic model + loader for the canonical JSON
│   │   └── graph_style.json               # CANONICAL single source of truth (colors/shapes/sizes/
│   │                                      #   severity ramp / phase order / edge styles / thresholds)
│   ├── cli/
│   │   ├── html_report.py                 # consume shared spec; richer controls; layout/cluster/scrubber (P1-P3)
│   │   └── visualizations/__init__.py     # source of the phase-band layout logic to port
│   └── web/
│       ├── models.py                      # PhaseResultRow: + graph_state_json column (P3)
│       ├── schemas.py                      # PhaseResultSchema: + graph_state (P3)
│       ├── routes/runs.py                  # expose per-phase graph states (P3)
│       ├── services/run_manager.py        # persist pr.graph_state per phase (P3)
│       └── migrations/003_phase_graph_state.py   # NEW Alembic migration (P3)

ui/
├── src/
│   ├── components/graph/
│   │   ├── KnowledgeGraph.tsx             # orchestrator: layout modes, filters, clustering, walker, scrubber
│   │   ├── graphStyle.ts                  # imports canonical graph_style.json; typed accessors (P4)
│   │   ├── graphMapping.ts                # graphState -> vis nodes/edges (pure, Vitest-tested) (P1-P3)
│   │   ├── layouts.ts                      # force / hierarchical-by-phase / centrality layout helpers (P1)
│   │   ├── GraphLegend.tsx                 # legend-as-filter (types/edges/severity) (P1)
│   │   ├── GraphControls.tsx              # layout toggle, cluster, scrubber, walker controls (P1-P3)
│   │   └── *.test.ts                       # Vitest unit tests for pure modules
│   ├── api/runs.ts                         # types/hook updates for per-phase states (P3)
│   ├── types/index.ts                      # GraphNode/Edge/State: centrality, severity, phase fields
│   └── pages/RunDetail.tsx                 # integrate scrubber + cross-linking with findings/attack log (P2-P3)
└── tests/e2e/                              # Playwright flows per user story

tests/                                      # backend pytest mirrors ziran/ layout
├── unit/ ...                               # graph export, style loader/parity, mapping
└── integration/ ...                        # per-phase persistence round-trip, API contract
```

**Structure Decision**: Web application (Option 2) with an added CLI report generator. The one cross-cutting addition is `ziran/interfaces/graph_style/` holding the **canonical JSON style/mapping spec** plus a typed Python loader. The UI consumes the same JSON (imported at build time via a Vite path alias to the canonical file), and a parity test asserts the TS-side typed view and the Python-side loaded model agree. This keeps a single source of truth without forcing the self-contained report to depend on the JS bundle or vice versa.

## Phased Delivery (PRs against `develop`)

- **PR1 — P4 + P1** (`feat`): canonical style spec + loader + parity test; `export_state()` centrality enrichment; hierarchical-by-phase + force layout toggle (UI + report); importance encoding (size∝centrality, severity color/border, dangerous marker); legend-as-filter (types/edges/severity). Ships the "less flat" MVP for both surfaces.
- **PR2 — P2** (`feat`): clustering + auto-cluster threshold; attack-chain walker; node↔finding/attack-log/OWASP-ATLAS cross-linking; multi-agent topology rendering.
- **PR3 — P3** (`feat`): migration + per-phase snapshot persistence + API exposure + schema; phase scrubber (UI + report); attack-relevant edge emphasis; empty/large-graph UX polish; older-run fallback.

Each PR is independently testable (maps to one or two user stories), passes all quality gates, and keeps CI green before the next begins.

## Complexity Tracking

No constitution violations — section intentionally empty.
