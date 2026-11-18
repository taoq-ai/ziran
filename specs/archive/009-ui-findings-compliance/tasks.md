# Tasks: UI Batch 2 — Findings Management, Compliance & Design System

**Input**: Design documents from `/specs/009-ui-findings-compliance/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included as the constitution requires >= 85% coverage.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: New dependencies, database migration, and shared models

- [x] T001 Install `@tanstack/react-table` in `ui/` — run `npm install @tanstack/react-table`
- [x] T002 Add `pyyaml` to the `ui` optional dependency group in `pyproject.toml` (needed for YAML export) — already a core dependency
- [x] T003 Create Alembic migration `ziran/interfaces/web/migrations/versions/002_findings_schema.py` — create tables `findings`, `compliance_mappings`, `export_jobs` with all columns, indexes, and constraints per data-model.md
- [x] T004 [P] Add `Finding`, `ComplianceMapping`, `ExportJob` SQLAlchemy models to `ziran/interfaces/web/models.py` — all fields per data-model.md, relationships (Finding.compliance_mappings, Run.findings), indexes, check constraints
- [x] T005 [P] Add Pydantic schemas to `ziran/interfaces/web/schemas.py` — `FindingSummary`, `FindingDetail`, `FindingStatusUpdate`, `BulkStatusUpdate`, `BulkStatusResponse`, `FindingListResponse`, `FindingStats`, `OwaspCategoryStatus`, `OwaspComplianceResponse`, `ComplianceSummary`
- [x] T006 [P] Add TypeScript types to `ui/src/types/index.ts` — `Finding`, `FindingSummary`, `FindingDetail`, `FindingStats`, `FindingStatus`, `Severity`, `OwaspCategory`, `OwaspComplianceResponse`, `ComplianceSummary`, `BulkStatusResponse`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Findings extraction service that MUST be complete before any UI or API can work

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Tests for Foundational

- [x] T007 [P] Create `tests/unit/test_findings_extractor.py` — test `FindingsExtractor.extract()`: given a Run with result_json containing attack_results, verify findings rows are created; test fingerprint dedup (same vector+target+category → single finding); test owasp_mapping → compliance_mappings rows; test only successful attacks are extracted; test empty attack_results produces no findings
- [x] T008 [P] Create `tests/unit/test_findings_schemas.py` — test `FindingSummary`, `FindingDetail`, `FindingStatusUpdate`, `BulkStatusUpdate` serialization/validation; test invalid severity/status values rejected; test `FindingStats` aggregation shape

### Implementation for Foundational

- [x] T009 Create `ziran/interfaces/web/services/findings_extractor.py` — `FindingsExtractor` class with async `extract(session: AsyncSession, run: Run) -> list[Finding]` method: deserialize `run.result_json` → `CampaignResult`, iterate `attack_results` where `successful == True`, compute `fingerprint = sha256(target_agent + vector_id + category)`, upsert into `findings` table (on fingerprint conflict: update run_id but preserve status), create `compliance_mappings` from `owasp_mapping[]`. Include `_compute_fingerprint()` and `_build_title()` helper methods.
- [x] T010 Modify `ziran/interfaces/web/services/run_manager.py` — after scan completion (where `run.result_json` is set), call `FindingsExtractor().extract(session, run)` to populate findings. Import and instantiate extractor. Add error handling that logs extraction failures but doesn't fail the run.

**Checkpoint**: Foundation ready — findings are auto-extracted after scans. API and UI can now build on this data.

---

## Phase 3: User Story 4 — Findings Database Schema & API (Priority: P1)

**Goal**: REST API for findings CRUD with filtering, pagination, status updates, bulk actions, and statistics.

**Independent Test**: Call `GET /api/findings` with various filter combinations, verify correct results and pagination. Call `PATCH /api/findings/{id}/status`, verify status persists. Call `POST /api/findings/bulk-status`, verify all findings update.

### Tests for User Story 4

- [ ] T011 [P] [US4] Create `tests/integration/test_findings_api.py` — test `GET /api/findings` (no filters, with severity filter, with status filter, with search, with pagination, with sort); test `GET /api/findings/{id}` (found, not found); test `PATCH /api/findings/{id}/status` (valid status, invalid status, not found); test `POST /api/findings/bulk-status` (valid, empty list); test `GET /api/findings/stats` (verify aggregation shape). Use httpx AsyncClient with TestClient.

### Implementation for User Story 4

- [x] T012 [US4] Create `ziran/interfaces/web/routes/findings.py` — FastAPI router with all endpoints per contracts/api.md: `GET /api/findings` (list with filtering, search via `ILIKE`, sorting, pagination), `GET /api/findings/{id}` (detail with compliance_mappings eager-loaded), `PATCH /api/findings/{id}/status` (update status + status_changed_at), `POST /api/findings/bulk-status` (bulk update via `WHERE id IN(...)`), `GET /api/findings/stats` (aggregate counts via `GROUP BY` queries for severity, status, category, owasp)
- [x] T013 [US4] Register findings router in `ziran/interfaces/web/app.py` — import and include `findings_router` at `/api` prefix alongside existing runs and health routers

**Checkpoint**: User Story 4 complete — full findings API functional with all CRUD operations

---

## Phase 4: User Story 2 — TaoQ Design System (Priority: P1)

**Goal**: Apply TaoQ branding (teal accent, dark-first, DM Sans, severity colors) across all UI components.

**Independent Test**: Open UI, verify dark background `#0a0a0a`, teal accent on buttons/links, DM Sans font, TaoQ logo in sidebar, severity badges with semantic colors, light mode toggle works.

### Implementation for User Story 2

- [x] T014 [US2] Update `ui/tailwind.config.ts` — extend colors with TaoQ tokens: `accent: '#4fd1c5'`, `accent-hover: '#38b2ac'`, `accent-light: '#81e6d9'`, background shades (`bg-primary: '#0a0a0a'`, `bg-secondary: '#111111'`, `bg-tertiary: '#1a1a1a'`), `border: '#27272a'`, severity colors (`danger: '#f87171'`, `warning-orange: '#fb923c'`, `warning-yellow: '#fbbf24'`, `safe: '#4ade80'`, `muted: '#71717a'`), foreground colors. Set `fontFamily.sans: ['DM Sans', ...]`. Set `darkMode: 'class'`.
- [x] T015 [US2] Update `ui/src/index.css` — add `@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap')` for DM Sans font. Update Tailwind CSS layer with TaoQ CSS custom properties for shadcn/ui theming (--background, --foreground, --primary, --accent, --destructive, etc.) for both dark (default) and light modes.
- [x] T016 [P] [US2] Create `ui/src/components/layout/ThemeToggle.tsx` — dark/light mode toggle button using lucide-react `Sun`/`Moon` icons. Read/write `localStorage('theme')`. Toggle `dark` class on `<html>` element. Default to dark.
- [x] T017 [P] [US2] Create `ui/src/components/findings/SeverityBadge.tsx` — reusable badge component with semantic colors: Critical=red (`bg-red-500/20 text-red-400`), High=orange, Medium=yellow, Low=teal, Info=gray. Use shadcn/ui `Badge` with `variant` prop.
- [x] T018 [US2] Update `ui/src/components/layout/Sidebar.tsx` — add TaoQ logo/brand at top, add `Findings` nav link (lucide `AlertTriangle` icon) and `Compliance` nav link (lucide `Shield` icon), integrate `ThemeToggle` at bottom of sidebar
- [x] T019 [US2] Update `ui/src/App.tsx` — add routes for `/findings` → Findings page, `/compliance` → Compliance page. Add `dark` class to root HTML element by default.
- [x] T020 [US2] Update existing pages (`ui/src/pages/Dashboard.tsx`, `ui/src/pages/NewRun.tsx`, `ui/src/pages/RunDetail.tsx`) — apply TaoQ design tokens to all existing components: update card backgrounds to `bg-secondary`, border colors to `border`, text colors to `foreground/foreground-secondary`, button styles to teal accent. Use `SeverityBadge` for any severity display.

**Checkpoint**: User Story 2 complete — all pages render with TaoQ branding, dark mode default, light mode toggle works

---

## Phase 5: User Story 1 — Findings Management Page (Priority: P1)

**Goal**: Sortable, filterable findings table with detail view, status management, and bulk actions.

**Independent Test**: Navigate to /findings, see findings table with all columns, filter by severity, open finding detail, change status, bulk select + status change.

**Depends on**: Phase 3 (findings API) and Phase 4 (design system for SeverityBadge)

### Implementation for User Story 1

- [x] T021 [US1] Create `ui/src/api/findings.ts` — TanStack Query hooks: `useFindings(filters)` (GET /api/findings with query params), `useFinding(id)` (GET /api/findings/{id}), `useUpdateFindingStatus()` (PATCH mutation), `useBulkUpdateStatus()` (POST mutation), `useFindingStats(filters)` (GET /api/findings/stats). Include filter parameter types.
- [x] T022 [US1] Create `ui/src/components/findings/FindingFilters.tsx` — filter bar with: severity dropdown (multi-select), status dropdown (multi-select), category dropdown, target agent dropdown, OWASP category dropdown, text search input. Emit filter changes via callback prop. Use shadcn/ui `Select`, `Input` components.
- [x] T023 [US1] Create `ui/src/components/findings/FindingsTable.tsx` — TanStack Table with columns: checkbox (selection), severity (SeverityBadge), title, category, target, status (dropdown), created_at. Sortable columns via server-side sort param. Row selection via TanStack's `getRowSelectionState`. Pagination controls (page size selector, prev/next). Empty state for no results.
- [x] T024 [US1] Create `ui/src/components/findings/FindingDetail.tsx` — detail drawer/dialog (shadcn/ui `Sheet` or `Dialog`): finding header (title, severity badge, status), attack transcript section (prompt_used, agent_response in code blocks), evidence section, detection metadata, remediation guidance, compliance mappings list, status change buttons (Open, Fixed, False Positive, Ignored).
- [x] T025 [US1] Create `ui/src/components/findings/BulkActions.tsx` — toolbar that appears when rows are selected: shows count of selected items, dropdown to set status (Fixed, False Positive, Ignored, Open), "Apply" button that calls `useBulkUpdateStatus`. Clears selection after success.
- [x] T026 [US1] Create `ui/src/pages/Findings.tsx` — compose FindingFilters, FindingsTable, BulkActions, FindingDetail. Manage filter state. Pass filters to `useFindings` hook. Show FindingStats summary cards at top (total, by severity). Open FindingDetail on row click. Wire all filter/sort/pagination changes to API calls.

**Checkpoint**: User Story 1 complete — full findings management workflow functional

---

## Phase 6: User Story 3 — OWASP LLM Top 10 Compliance Matrix (Priority: P2)

**Goal**: 10-cell OWASP grid with finding counts, severity colors, click-to-filter, tooltip descriptions.

**Independent Test**: Navigate to compliance page, see 10-cell grid with correct category names, finding counts, and color coding. Click a cell, verify navigation to findings filtered by that OWASP category.

**Depends on**: Phase 3 (findings API for data), Phase 4 (design system for colors)

### Tests for User Story 3

- [ ] T027 [P] [US3] Create `tests/integration/test_compliance_api.py` — test `GET /api/compliance/owasp` returns all 10 categories with correct structure; test with run_id filter; test status logic (critical findings → "critical", no findings → "not_tested"); test summary counts.

### Implementation for User Story 3

- [x] T028 [US3] Create `ziran/interfaces/web/routes/compliance.py` — FastAPI router with `GET /api/compliance/owasp` endpoint: query `findings` → `compliance_mappings` joined, group by `control_id`, compute per-category finding counts by severity, determine status (critical/warning/pass/not_tested), include OWASP descriptions from `OwaspLlmCategory` enum and `OWASP_LLM_DESCRIPTIONS`. Support optional `run_id` filter.
- [x] T029 [US3] Register compliance router in `ziran/interfaces/web/app.py` — import and include `compliance_router` at `/api` prefix
- [x] T030 [US3] Create `ui/src/api/compliance.ts` — TanStack Query hook `useOwaspCompliance(runId?)` for `GET /api/compliance/owasp`
- [x] T031 [US3] Create `ui/src/components/compliance/OwaspMatrix.tsx` — responsive 2×5 grid (or 5×2 on mobile) of 10 cells. Each cell: category ID (LLM01–LLM10), short name, finding count badge, background color based on status (red=critical, orange=warning, green=pass, gray=not_tested). On click: navigate to `/findings?owasp={control_id}`. On hover: tooltip with full description. Use TaoQ severity colors.
- [x] T032 [US3] Create `ui/src/pages/Compliance.tsx` — page that renders OwaspMatrix with summary stats (tested count, categories with findings, categories with critical). Include link to Findings page.
- [x] T033 [US3] Add OwaspMatrix component to `ui/src/pages/RunDetail.tsx` — show OWASP compliance matrix section below phase results, scoped to current run (pass `runId` prop to `useOwaspCompliance`).

**Checkpoint**: User Story 3 complete — OWASP matrix displays on both Compliance page and Run Detail page

---

## Phase 7: User Story 5 — Community Export Endpoints (Priority: P3)

**Goal**: CSV, JSON, YAML, and Markdown export endpoints for findings and runs.

**Independent Test**: Call `GET /api/export/findings.csv` with severity=critical filter, verify CSV file with correct headers and filtered data. Call `GET /api/export/run/{id}.md`, verify Markdown report structure.

### Tests for User Story 5

- [ ] T034 [P] [US5] Create `tests/integration/test_export_api.py` — test CSV export (verify headers, filtered data, Content-Type, Content-Disposition); test JSON export (verify array of findings); test YAML export (verify valid YAML with run config); test Markdown export (verify report sections); test export with no matching findings (empty CSV with headers).

### Implementation for User Story 5

- [x] T035 [US5] Create `ziran/interfaces/web/routes/export.py` — FastAPI router with endpoints per contracts/api.md: `GET /api/export/findings.csv` (StreamingResponse with csv.writer, apply same filters as findings list), `GET /api/export/findings.json` (return all matching findings as JSON array with Content-Disposition), `GET /api/export/run/{id}.yaml` (yaml.dump of run config_json), `GET /api/export/run/{id}.md` (Markdown template with title, summary stats, findings table, OWASP coverage, configuration). All endpoints set correct Content-Type and Content-Disposition headers.
- [x] T036 [US5] Register export router in `ziran/interfaces/web/app.py` — import and include `export_router` at `/api` prefix
- [x] T037 [US5] Create `ui/src/api/export.ts` — download helper functions: `downloadFindingsCsv(filters)`, `downloadFindingsJson(filters)`, `downloadRunYaml(runId)`, `downloadRunMarkdown(runId)`. Each triggers a browser download via `window.open()` or fetch + blob.
- [x] T038 [US5] Add export buttons to `ui/src/pages/Findings.tsx` — dropdown menu with "Export CSV" and "Export JSON" options. Pass current filter state to download functions.
- [x] T039 [US5] Add export buttons to `ui/src/pages/RunDetail.tsx` — dropdown menu with "Export YAML" and "Export Markdown" options for current run.

**Checkpoint**: User Story 5 complete — all 4 export formats functional with correct Content-Type headers

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Quality gates, linting, type checking, and validation

- [x] T040 Run `uv run ruff check .` and fix any lint violations in all new Python files
- [x] T041 Run `uv run ruff format .` and fix any formatting issues in all new Python files
- [x] T042 Run `uv run mypy ziran/` and fix any type errors in new Python files (strict mode)
- [x] T043 Run `uv run pytest --cov=ziran` and verify all tests pass with coverage >= 85%
- [x] T044 Run `cd ui && npx tsc --noEmit` and fix any TypeScript errors in new frontend files
- [x] T045 Validate quickstart.md — verify end-user and developer workflows work as documented

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 (models + migration must exist)
- **User Story 4 / API (Phase 3)**: Depends on Phase 2 (extractor must populate findings)
- **User Story 2 / Design (Phase 4)**: Depends on Phase 1 only (TS types). Can run in parallel with Phase 2 and 3.
- **User Story 1 / UI (Phase 5)**: Depends on Phase 3 (API) and Phase 4 (design system)
- **User Story 3 / OWASP (Phase 6)**: Depends on Phase 3 (API) and Phase 4 (design system)
- **User Story 5 / Export (Phase 7)**: Depends on Phase 3 (findings data in DB)
- **Polish (Phase 8)**: Depends on all previous phases

### User Story Dependencies

- **US4 (Findings API)**: Depends on Foundational only — delivers the backend data layer
- **US2 (Design System)**: Independent of other stories — can start after Setup
- **US1 (Findings UI)**: Depends on US4 (API) and US2 (design system) — assembles the frontend
- **US3 (OWASP Matrix)**: Depends on US4 (API) and US2 (design system)
- **US5 (Export)**: Depends on US4 (API) only — backend-only endpoints

### Within Each User Story

- Tests written first (TDD where applicable)
- Models/schemas before services
- Services before routes
- Backend routes before frontend hooks
- Frontend hooks before frontend components
- Components before page assembly

### Parallel Opportunities

- T004, T005, T006 (Setup): All touch different files — fully parallel
- T007, T008 (Foundational tests): Different test files — parallel
- T016, T017 (Design): ThemeToggle and SeverityBadge are independent components — parallel
- T027, T034 (Tests for US3, US5): Different test files — parallel
- Phase 4 (Design) can run in parallel with Phases 2 and 3 (backend work)

---

## Parallel Example: Setup Phase

```bash
# These tasks touch different files and can run in parallel:
T004: "Add Finding, ComplianceMapping, ExportJob models to ziran/interfaces/web/models.py"
T005: "Add Pydantic schemas to ziran/interfaces/web/schemas.py"
T006: "Add TypeScript types to ui/src/types/index.ts"
```

## Parallel Example: Design System (Phase 4)

```bash
# After tailwind.config.ts and index.css are done:
T016: "Create ThemeToggle.tsx in ui/src/components/layout/"
T017: "Create SeverityBadge.tsx in ui/src/components/findings/"
```

---

## Implementation Strategy

### MVP First (User Stories 4 + 2 + 1)

1. Complete Phase 1: Setup (T001–T006)
2. Complete Phase 2: Foundational (T007–T010)
3. Complete Phase 3: User Story 4 — Findings API (T011–T013)
4. Complete Phase 4: User Story 2 — Design System (T014–T020)
5. Complete Phase 5: User Story 1 — Findings UI (T021–T026)
6. **STOP and VALIDATE**: Findings management workflow end-to-end

### Incremental Delivery

1. Setup + Foundational → Findings auto-extracted after scans
2. Add US4 (API) → Backend fully queryable
3. Add US2 (Design) → UI branded and consistent
4. Add US1 (UI) → Full findings management (MVP!)
5. Add US3 (OWASP) → Compliance matrix adds compliance value
6. Add US5 (Export) → Download capabilities
7. Polish → Quality gates pass

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- The design system (US2) is implemented before the findings UI (US1) because US1 depends on SeverityBadge and TaoQ tokens
- Findings extraction (Foundational) must complete before any API endpoints, as they query the findings table
- Export endpoints (US5) are backend-only; frontend buttons are added in the same phase for completeness
- All backend code must pass `ruff check`, `ruff format`, `mypy --strict`, and `pytest --cov >= 85%`
