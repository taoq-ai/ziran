# Tasks: UI Batch 3 — Pages, Polish & Docker

**Input**: Design documents from `/specs/010-ui-polish-pages/`

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)

---

## Phase 1: Setup

- [ ] T001 Install `vis-data` and `vis-network` npm packages in `ui/`
- [ ] T002 [P] Add Pydantic schemas for library and config presets in `ziran/interfaces/web/schemas.py` — `VectorSummary`, `VectorDetail`, `PromptTemplate`, `LibraryStatsResponse`, `VectorListResponse`, `ConfigPresetCreate`, `ConfigPresetUpdate`, `ConfigPresetResponse`
- [ ] T003 [P] Add TypeScript types for library vectors and config presets in `ui/src/types/index.ts`

---

## Phase 2: US1 — Knowledge Graph Visualization (#99)

**Goal**: Interactive graph on Run Detail page from graph_state_json.

- [ ] T004 [US1] Create `ui/src/components/graph/KnowledgeGraph.tsx` — vis-network component receiving graph_state_json, rendering nodes with correct colors/shapes/sizes (port constants from html_report.py), edge colors and dashes, physics toggle, fit view button, search input, node click detail overlay
- [ ] T005 [US1] Integrate KnowledgeGraph into `ui/src/pages/RunDetail.tsx` — add graph section below stats cards, pass graph_state_json from run detail data, show empty state when no graph data
- [ ] T006 [US1] Add critical path highlighting — when user clicks a critical path from the vulnerability list, highlight those nodes/edges in the graph and dim others

---

## Phase 3: US2 — Attack Library Browser (#100)

**Goal**: Browsable, searchable page for all bundled attack vectors.

- [ ] T007 [US2] Create `ziran/interfaces/web/routes/library.py` — `GET /api/library/vectors` (filtering by category, severity, phase, owasp, search), `GET /api/library/vectors/{vector_id}`, `GET /api/library/stats`. Instantiate `AttackLibrary` and return vector metadata.
- [ ] T008 [US2] Register library router in `ziran/interfaces/web/app.py`
- [ ] T009 [US2] Create `ui/src/api/library.ts` — TanStack Query hooks: `useVectors(filters)`, `useVectorDetail(id)`, `useLibraryStats()`
- [ ] T010 [US2] Create `ui/src/components/library/VectorTable.tsx` — sortable table with columns: Name, Category (badge), Severity (badge), Phase, OWASP, Prompts, Tags. Filter bar at top.
- [ ] T011 [US2] Create `ui/src/components/library/VectorDetail.tsx` — expandable row or modal showing description, references, prompt templates with variables, success/failure indicators
- [ ] T012 [US2] Rewrite `ui/src/pages/Library.tsx` — replace placeholder with stats cards + VectorTable + search/filter, connect to library API hooks

---

## Phase 4: US3 — Config Presets & Settings (#101)

**Goal**: CRUD presets, Settings page, preset selector on New Run.

- [ ] T013 [US3] Create `ziran/interfaces/web/routes/configs.py` — `GET /api/configs`, `POST /api/configs`, `PUT /api/configs/{id}`, `DELETE /api/configs/{id}`. Use existing ConfigPreset model.
- [ ] T014 [US3] Register configs router in `ziran/interfaces/web/app.py`
- [ ] T015 [US3] Create `ui/src/api/configs.ts` — TanStack Query hooks: `useConfigs()`, `useCreateConfig()`, `useUpdateConfig()`, `useDeleteConfig()`
- [ ] T016 [US3] Rewrite `ui/src/pages/Settings.tsx` — replace placeholder with preset list (name, description, edit/delete buttons), create preset form, default scan settings section
- [ ] T017 [US3] Add preset selector dropdown to `ui/src/pages/NewRun.tsx` — fetch presets, populate form on selection, "Save as Preset" button

---

## Phase 5: US4 — UX Polish (#104)

**Goal**: Skeletons, error boundaries, empty states, responsive, 404.

- [ ] T018 [P] [US4] Create `ui/src/components/ui/Skeleton.tsx` — shadcn-style skeleton loader component
- [ ] T019 [P] [US4] Create `ui/src/components/ui/ErrorBoundary.tsx` — React error boundary wrapping page content, shows error message + retry button
- [ ] T020 [P] [US4] Create `ui/src/pages/NotFound.tsx` — 404 page with message and link back to Dashboard
- [ ] T021 [US4] Add skeleton loaders to `ui/src/pages/Dashboard.tsx`, `Findings.tsx`, `Library.tsx`, `RunDetail.tsx` — show skeletons while data is loading
- [ ] T022 [US4] Add meaningful empty states to all pages — Dashboard (no runs → CTA), Library (no filter matches), Findings (no findings), RunDetail (no vulnerabilities → success message)
- [ ] T023 [US4] Make sidebar responsive in `ui/src/components/layout/Sidebar.tsx` — collapse to hamburger menu below md breakpoint, overlay menu on mobile
- [ ] T024 [US4] Add ErrorBoundary wrapping to `ui/src/App.tsx` and 404 route

---

## Phase 6: US5 — Docker Support (#102)

**Goal**: `docker compose up` starts working ZIRAN UI with PostgreSQL.

- [ ] T025 [P] [US5] Create `Dockerfile` — multi-stage: Node builder (npm ci + npm run build), Python runtime (pip install .[ui], copy static, expose 8484)
- [ ] T026 [P] [US5] Create `docker-compose.yml` — ziran-ui service + postgres service, persistent volume, env_file
- [ ] T027 [P] [US5] Create `.env.example` — document ZIRAN_DATABASE_URL, LLM provider, API keys
- [ ] T028 [US5] Create `.dockerignore` — exclude .git, node_modules, __pycache__, .venv, dist, .env

---

## Phase 7: US6 — Export UI Buttons (#174)

**Goal**: Add export buttons to Findings and RunDetail pages.

- [ ] T029 [US6] Add export dropdown button to `ui/src/pages/Findings.tsx` — CSV and JSON options, passes current filters to export API
- [ ] T030 [US6] Add export dropdown button to `ui/src/pages/RunDetail.tsx` — Markdown and YAML options for current run

---

## Phase 8: Polish & Validation

- [ ] T031 Run `uv run ruff check .` and fix any lint violations
- [ ] T032 Run `uv run ruff format .` and fix any formatting issues
- [ ] T033 Run `uv run mypy ziran/` and fix any type errors
- [ ] T034 Run `uv run pytest --cov=ziran` and verify all tests pass
- [ ] T035 Create unit tests for library and configs routes in `tests/unit/test_library_api.py` and `tests/unit/test_configs_api.py`

---

## Dependencies

- **Phase 1**: No dependencies — setup
- **Phase 2 (US1)**: Depends on T001 (vis-network installed)
- **Phase 3 (US2)**: Depends on T002, T003 (schemas/types)
- **Phase 4 (US3)**: Depends on T002, T003 (schemas/types)
- **Phase 5 (US4)**: Independent — can run in parallel with Phases 2-4
- **Phase 6 (US5)**: Independent — no code dependencies
- **Phase 7 (US6)**: Depends on Findings and RunDetail pages existing
- **Phase 8**: Depends on all previous phases

## Parallel Opportunities

- T002, T003: Different files (Python schemas vs TypeScript types)
- T018, T019, T020: Different component files
- T025, T026, T027, T028: Different Docker files
- Phases 2, 3, 4, 5, 6 can all run in parallel (different files/concerns)
