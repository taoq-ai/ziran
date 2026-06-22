---
description: "Task breakdown for Interactive Knowledge Graph Visualization"
---

# Tasks: Interactive Knowledge Graph Visualization

**Input**: Design documents from `/specs/026-interactive-knowledge-graph/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included — the project constitution (Principle III) mandates unit + integration coverage (Python ≥ 85%). Frontend pure-logic tests use Vitest; acceptance flows use Playwright.

**Organization**: Tasks are grouped by user story. PR grouping (against `develop`): **PR1 = Phases 1–4 (US4 + US1)**, **PR2 = Phase 5 (US2)**, **PR3 = Phase 6 (US3)**, plus Polish folded into each PR.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 (P1 structure), US2 (P2 drill-down), US3 (P3 temporal), US4 (P4 shared spec)

## Path Conventions

Backend: `ziran/...`, tests in `tests/unit/` and `tests/integration/`. Frontend: `ui/src/...`, unit tests colocated `*.test.ts`, E2E in `ui/tests/e2e/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Tooling and scaffolding shared by all stories.

- [~] T001 [P] Add Vitest + @testing-library/react — **DEFERRED**: the package registry is locked down in the dev environment; installing Vitest would bypass the org's supply-chain control. Tracked for a follow-up once the dep can be added through the org registry. Pure modules are verified via `npm run build` (tsc) + Playwright E2E in the meantime.
- [X] T002 [P] Add Vite path alias `@graphstyle` → `ziran/interfaces/graph_style/graph_style.json` in `ui/vite.config.ts` + matching path in `ui/tsconfig.app.json` (with `resolveJsonModule`)
- [X] T003 Create `ziran/interfaces/graph_style/__init__.py` package directory

**Checkpoint**: Build/test tooling ready for the shared spec and frontend unit tests.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Backend graph enrichment and shared types that ALL rendering features depend on.

**⚠️ CRITICAL**: No user story rendering work can begin until this phase is complete.

- [X] T004 Enrich `export_state()` in `ziran/application/knowledge_graph/graph.py` to attach normalized betweenness `centrality` and derived earliest-discovery `phase` to every exported node; never drop nodes missing data (centrality capped above 800 nodes for performance)
- [X] T005 [P] Add unit test in `tests/unit/test_graph_export_enrichment.py` asserting nodes carry normalized `centrality` (0–1) and derived `phase` (or omitted → unassigned), with graceful defaults + cache persistence
- [X] T006 [P] Extend UI graph types in `ui/src/types/index.ts`: optional `centrality`/`severity`/`phase`/`dangerous`/`risk_score` on `GraphNode`, `risk_score`/`chain_position` on `GraphEdge`; `graph_state?` on UI `PhaseResult`

**Checkpoint**: Exported graph carries importance + phase signals; UI types ready.

---

## Phase 3: User Story 4 - Consistent graph across UI & report (Priority: P1, enabling refactor)

**Goal**: One canonical style/mapping spec consumed by both the web UI and the self-contained HTML report; eliminate the duplicated styling constants.

**Independent Test**: Change a node color/shape in `graph_style.json`, rebuild the UI and regenerate the report — both reflect the change with no surface-specific edits.

### Tests for User Story 4

- [X] T007 [P] [US4] Python unit test in `tests/unit/test_graph_style_spec.py`: canonical JSON loads + validates; node/edge type key sets equal the known type enums; accessors + 100% module coverage
- [X] T008 [P] [US4] Python unit test for `graph_state_to_vis` (in `tests/unit/test_html_report.py`): derives colors/shapes/sizes from the spec, danger marker on dangerous nodes, size scales with `centrality`, phase level, attack-edge emphasis
- [~] T009 [P] [US4] Vitest parity test for `graphMapping.ts` — **DEFERRED** with T001 (Vitest registry block). Parity is preserved structurally: `graphMapping.ts` mirrors `_node_to_vis`/`_edge_to_vis` against the same shared JSON.
- [X] T010 [US4] Create canonical `ziran/interfaces/graph_style/graph_style.json`: all 7 node types, all 11 edge types, severity_ramp, danger_marker, phase_order, size_encoding, attack_edge_types, thresholds
- [X] T011 [US4] Create `ziran/interfaces/graph_style/spec.py`: Pydantic model + cached loader (fail-fast validation) with typed accessors (`node_style`/`edge_style`/`severity_color`/`node_size`/`phase_level`/`is_attack_edge`)
- [X] T012 [US4] Refactor `graph_state_to_vis()` + remove `_NODE_*`/`_EDGE_*` constants in `html_report.py` to consume the spec; bump report vis-network CDN to 10.0.2 (matches UI)
- [X] T013 [P] [US4] Create `ui/src/components/graph/graphStyle.ts`: imports `@graphstyle` JSON, typed accessors mirroring `spec.py`
- [X] T014 [US4] Create `ui/src/components/graph/graphMapping.ts`: pure `graphState → vis nodes/edges` mapping reading all values from `graphStyle.ts`
- [X] T015 [US4] Refactor `ui/src/components/graph/KnowledgeGraph.tsx` to drop the duplicated constants and render via `graphMapping.ts`/`graphStyle.ts`

**Checkpoint**: Both surfaces render from one source of truth; styling change propagates to both.

---

## Phase 4: User Story 1 - Read campaign structure at a glance (Priority: P1) 🎯 MVP

**Goal**: Hierarchical-by-phase + force layout toggle, importance encoding (size∝centrality, severity color/border, dangerous marker), and legend-as-filter for node types / edge types / severity bands — on both surfaces.

**Independent Test**: Open a multi-phase run, switch to hierarchical layout (nodes band by phase in methodology order), confirm central nodes are larger and high-severity nodes emphasized, and toggle a node type / severity band in the legend to hide/show.

### Tests for User Story 1

- [~] T016 [P] [US1] Vitest unit test for `layouts.ts` — **DEFERRED** with T001 (Vitest registry block). Hierarchical banding is covered by the Python `phase_level` tests + the E2E layout-toggle test.
- [X] T017 [P] [US1] Playwright E2E `ui/e2e/graph-structure.spec.ts`: layout toggle pressed-state, legend node-type + severity filter toggles (acceptance scenarios US1.1–US1.5). Runs in CI against a served app.

### Implementation for User Story 1

- [X] T018 [P] [US1] Create `ui/src/components/graph/layouts.ts`: force-directed, hierarchical-by-phase (vis `layout.hierarchical` LR + node levels), and a centrality physics mode
- [X] T019 [US1] Importance encoding in `graphMapping.ts`: size from `centrality` (spec `size_encoding`), severity color/border from `severity_ramp`, danger marker from `danger_marker`
- [X] T020 [P] [US1] Create `ui/src/components/graph/GraphControls.tsx`: layout-mode toggle (force / hierarchical / centrality)
- [X] T021 [P] [US1] Create `ui/src/components/graph/GraphLegend.tsx`: legend that doubles as filter toggles for node types, edge types, and severity bands
- [X] T022 [US1] Wire layout toggle + legend filters + existing search/path-highlight into `KnowledgeGraph.tsx`, preserving filter/selection across layout switches (layout applied via `setOptions`, no rebuild)
- [X] T023 [US1] Add hierarchical layout toggle, importance encoding, and node-type/edge-type filters to the report `html_report.py` (inline JS, spec-driven)
- [X] T024 [P] [US1] Report unit tests (in `tests/unit/test_html_report.py`): generated HTML embeds the layout toggle, legend-as-filter, edge filter panel, and pinned vis-network 10.x CDN

**Checkpoint**: The "less flat" MVP works on both surfaces. **→ PR1 (US4 + US1) ready.** Vitest unit tests (T001/T009/T016) deferred pending registry access.

---

## Phase 5: User Story 2 - Drill into large graphs & walk attack chains (Priority: P2)

**Goal**: Clustering (collapse/expand by phase or type, auto-cluster above threshold), attack-chain walker, node↔finding/attack-log/OWASP-ATLAS cross-linking, and distinct multi-agent topology rendering.

**Independent Test**: Large multi-agent run → auto-clustered overview, expand a phase cluster; start the walker and step through a discovered path; click a vuln node → finding/attack-log/OWASP-ATLAS opens; activate a finding row → its node focuses; delegation/trust-boundary/context edges are visually distinct.

### Tests for User Story 2

- [~] T025 [P] [US2] Vitest unit test for `clustering.ts` — **DEFERRED** (Vitest registry block); grouping/auto-cluster logic verified via the E2E drill-down test.
- [~] T026 [P] [US2] Vitest unit test for the walker — **DEFERRED** (Vitest registry block); covered by the E2E walker-stepping test.
- [X] T027 [P] [US2] Playwright E2E `ui/e2e/graph-drilldown.spec.ts`: cluster control (incl. agent grouping), walker stepping (step indicator), node↔attack-log cross-link

### Implementation for User Story 2

- [X] T028 [P] [US2] Create `ui/src/components/graph/clustering.ts`: collapse/expand by phase/type via vis `cluster()`/`openCluster()`, agent grouping via `clusterByConnection`, auto-cluster above the spec threshold, labeled super-nodes
- [X] T029 [P] [US2] Create `ui/src/components/graph/AttackChainWalker.tsx`: select a path, step node-by-node with focus + context + position indicator; disabled when no paths
- [X] T030 [US2] Add clustering + walker controls to `GraphControls.tsx` and wire into `KnowledgeGraph.tsx`
- [X] T031 [US2] Multi-agent topology: distinct `delegates_to`/`trust_boundary`/`shares_context` styles (in the spec since PR1) + agent grouping via clustering
- [X] T032 [US2] Cross-linking in `RunDetail.tsx` + `AttackLogPanel.tsx`: node click → scroll/focus the attack-log card (vuln node `id` == `vector_id`); row activation → focus node; OWASP/ATLAS mappings surfaced on each row
- [X] T033 [US2] Report parity in `html_report.py`: inline clustering controls + `setCluster`, node→attack-log anchor scroll (`report-attack-{vector_id}`)
- [X] T034 [P] [US2] Report unit tests (in `tests/unit/test_html_report.py`): clustering JS + `clusterSelect` + cross-link anchors

**Checkpoint**: Large-graph navigation + investigation work on both surfaces. **→ PR2 (US2) ready.** Vitest unit tests (T025/T026) deferred pending registry access.

---

## Phase 6: User Story 3 - Watch the campaign grow over time (Priority: P3)

**Goal**: Persist per-phase graph snapshots, expose them via the API, add a phase scrubber, emphasize attack-relevant edges, and add empty/large-graph UX. Older runs fall back to final state.

**Independent Test**: Multi-phase run → scrubber grows the graph phase-by-phase ending at final state; legacy run → falls back to final state; attack edges emphasized; empty/filtered-to-empty shows a helpful state.

### Tests for User Story 3

- [ ] T035 [P] [US3] Integration test `tests/integration/test_phase_graph_persistence.py`: run with N phases → each `PhaseResultRow` persists `graph_state_json`; node counts are monotonic non-decreasing by `phase_index`; final phase equals `Run.graph_state_json`
- [ ] T036 [P] [US3] Integration test `tests/integration/test_runs_api_phase_graph.py`: `GET /api/runs/{id}` returns per-phase `graph_state` (per [contracts/runs-api.md](contracts/runs-api.md)); legacy run returns `null` per phase with final state still present
- [ ] T037 [P] [US3] Playwright E2E `ui/tests/e2e/graph-temporal.spec.ts`: scrubber growth + final-state match + empty-state (acceptance scenarios US3.1–US3.4)

### Implementation for User Story 3

- [ ] T038 [US3] Verify the Alembic config/entry path, then create migration `ziran/interfaces/web/migrations/003_phase_graph_state.py` (following the `NNN_description.py` convention after `002_findings_schema.py`): add nullable `graph_state_json` JSONB column to `phase_results`; correct quickstart.md if the alembic config path differs
- [ ] T039 [US3] Add `graph_state_json` column to `PhaseResultRow` in `ziran/interfaces/web/models.py`
- [ ] T040 [US3] Persist `pr.graph_state` per phase when inserting `PhaseResultRow` in `ziran/interfaces/web/services/run_manager.py`
- [ ] T041 [US3] Add nullable `graph_state` field to `PhaseResultSchema` in `ziran/interfaces/web/schemas.py` (verify it surfaces in `routes/runs.py` response)
- [ ] T042 [P] [US3] Add per-phase fetching/typing in `ui/src/api/runs.ts` and create `ui/src/components/graph/PhaseScrubber.tsx`: step the graph through ordered per-phase states with final-state fallback
- [ ] T043 [US3] Integrate the scrubber into `ui/src/pages/RunDetail.tsx` / `KnowledgeGraph.tsx`
- [ ] T044 [P] [US3] Attack-relevant edge emphasis (weight + directionality for `attack_edge_types`) in `graphMapping.ts`, `graphStyle.ts`/`graph_style.json`, and the report mapping
- [ ] T045 [P] [US3] Empty/large-graph UX: helpful empty + "nothing matches" states with reset in `KnowledgeGraph.tsx` and the report template
- [ ] T046 [US3] Add the phase scrubber + attack-edge emphasis + empty state to the report in `ziran/interfaces/cli/html_report.py` (embed per-phase states inline so the scrubber works offline)

**Checkpoint**: Temporal replay + polish on both surfaces. **→ PR3 (US3) ready.**

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Per-PR finishing (run the relevant subset before each PR; full pass before the last).

- [ ] T047 [P] Update `docs/` (and any graph/report user docs) to describe layout modes, filters, clustering, walker, cross-linking, and the phase scrubber
- [ ] T048 Run `quickstart.md` verification for each completed user story (per-story acceptance checks)
- [ ] T049 Quality gates per PR: `uv run ruff check . && uv run ruff format --check . && uv run mypy ziran/ && uv run pytest --cov=ziran` (≥ 85%); `cd ui && npm run build && npm run test:unit && npm run test:e2e`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS all user stories (centrality/phase enrichment + types).
- **US4 (Phase 3)**: depends on Foundational; the shared spec underpins US1–US3 rendering.
- **US1 (Phase 4)**: depends on US4 (renders via shared spec) + Foundational (centrality).
- **US2 (Phase 5)**: depends on US4 (+ US1 controls scaffold); independently testable.
- **US3 (Phase 6)**: depends on US4; backend persistence chain is internal (migration → model → run_manager → schema → API → UI scrubber).
- **Polish (Phase 7)**: per-PR.

### PR boundaries

- **PR1** = Phases 1–4 (US4 + US1) + relevant Polish → the MVP, both surfaces.
- **PR2** = Phase 5 (US2) + relevant Polish.
- **PR3** = Phase 6 (US3) + final Polish.

### Within US3 (strict order)

T038 → T039 → T040 → T041 (backend chain) before T042/T043 (UI scrubber). T044/T045 are parallel-safe.

### Parallel Opportunities

- Setup: T001, T002 parallel.
- Foundational: T005, T006 parallel (after T004 for T005).
- US4 tests T007–T009 parallel; T013 parallel with T010–T012 (different files).
- US1: T016/T017 parallel; T018/T020/T021 parallel; T024 parallel.
- US2: T025/T026/T027 parallel; T028/T029 parallel; T034 parallel.
- US3: T035/T036/T037 parallel; T044/T045 parallel.

---

## Implementation Strategy

### MVP First (PR1 = US4 + US1)

1. Phase 1 Setup → Phase 2 Foundational → Phase 3 US4 (shared spec) → Phase 4 US1 (structure/encoding/filters).
2. **STOP and VALIDATE**: both surfaces render structured, weighted, filterable graphs from one source of truth.
3. Open PR1 against `develop` with labels; confirm CI green.

### Incremental Delivery

- PR1 (MVP) → PR2 (drill-down/investigation) → PR3 (temporal/polish). Each adds value without breaking prior stories; each passes all quality gates and CI before the next begins.

---

## Notes

- [P] = different files, no incomplete-task dependency.
- Tests precede implementation within each story (constitution Principle III); verify they fail first.
- Never weaken styling parity: a value change in `graph_style.json` must reflect on both surfaces (US4 acceptance).
- Per CLAUDE.md: branch off `develop`, PRs target `develop`, add labels, check CI after every push.
