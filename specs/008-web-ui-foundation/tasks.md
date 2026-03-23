# Tasks: Web UI Foundation

**Input**: Design documents from `/specs/008-web-ui-foundation/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included as the constitution requires >= 85% coverage.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Package configuration and dependency setup

- [x] T001 Add `ui` optional dependency group (fastapi, uvicorn, sqlalchemy, asyncpg, websockets, alembic) to `pyproject.toml` and update `all` extra to include `ui`
- [x] T002 Add mypy overrides for `fastapi`, `uvicorn`, `sqlalchemy`, `asyncpg`, `alembic` in `pyproject.toml`
- [x] T003 Add `ziran/interfaces/web/static/` and `ui/node_modules/` to `.gitignore`
- [x] T004 Create `ziran/interfaces/web/__init__.py` with empty module docstring

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core backend infrastructure that MUST be complete before ANY user story can be implemented

**WARNING**: No user story work can begin until this phase is complete

- [x] T005 Create `ziran/interfaces/web/config.py` — `WebUIConfig` Pydantic settings model with `database_url` (from `ZIRAN_DATABASE_URL` env var, default `postgresql+asyncpg://localhost:5432/ziran`), `host` (default `127.0.0.1`), `port` (default `8484`), `dev_mode` (default `False`)
- [x] T006 Create `ziran/interfaces/web/models.py` — SQLAlchemy 2.0 async declarative base, `Run` model (UUID PK, target_agent, status, coverage_level, strategy, config_json JSONB, total_vulnerabilities, critical_paths_count, dangerous_chains_count, final_trust_score, total_tokens, result_json JSONB, graph_state_json JSONB, error, created_at, started_at, completed_at), `PhaseResultRow` model (UUID PK, run_id FK, phase, phase_index, success, trust_score, duration_seconds, token_usage_json JSONB, vulnerabilities_found JSONB, discovered_capabilities JSONB, error, created_at), `ConfigPreset` model (UUID PK, name UNIQUE, description, config_json JSONB, created_at, updated_at). Add indexes on `runs.status`, `runs.created_at`, `phase_results.run_id`
- [x] T007 Create `ziran/interfaces/web/schemas.py` — Pydantic response schemas: `HealthResponse` (status, version, database), `RunSummary`, `PhaseResultSchema`, `ConfigPresetSchema`. Import `ziran.__version__` for version field.
- [x] T008 Create `ziran/interfaces/web/dependencies.py` — async sessionmaker factory, `get_db()` async generator dependency yielding `AsyncSession`
- [x] T009 Create `ziran/interfaces/web/migrations/env.py` — Alembic async environment using `run_async()` with `create_async_engine`. Configure `target_metadata` from `models.Base.metadata`. No `alembic.ini` — configured programmatically.
- [x] T010 Create `ziran/interfaces/web/migrations/script.py.mako` — Alembic migration template
- [x] T011 Create `ziran/interfaces/web/migrations/versions/001_initial_schema.py` — initial migration creating `runs`, `phase_results`, `config_presets` tables with all columns and indexes from data-model.md
- [x] T012 Create `ziran/interfaces/web/routes/__init__.py` and `ziran/interfaces/web/routes/health.py` — `GET /api/health` endpoint returning `HealthResponse` with DB connectivity check per contracts/api.md

**Checkpoint**: Foundation ready — user story implementation can now begin

---

## Phase 3: User Story 1 — Launch Web Dashboard (Priority: P1) MVP

**Goal**: A user installs `ziran[ui]`, runs `ziran ui`, and sees a dashboard in the browser with sidebar navigation and health check endpoint.

**Independent Test**: Run `pip install -e ".[ui]"`, set `ZIRAN_DATABASE_URL`, run `ziran ui`, open browser at `http://127.0.0.1:8484`, verify dashboard loads and `/api/health` returns 200.

### Tests for User Story 1

- [x] T013 [P] [US1] Create `tests/unit/test_web_config.py` — test `WebUIConfig` default values, test env var override for `ZIRAN_DATABASE_URL`, test custom host/port
- [x] T014 [P] [US1] Create `tests/unit/test_web_models.py` — test `Run`, `PhaseResultRow`, `ConfigPreset` model instantiation with valid data, test UUID PK generation, test JSONB field defaults
- [x] T015 [P] [US1] Create `tests/unit/test_web_schemas.py` — test `HealthResponse` serialization, test `RunSummary` from `Run` model data
- [x] T016 [P] [US1] Create `tests/integration/test_web_app.py` — test `create_app()` returns FastAPI instance, test `GET /api/health` returns 200 with correct schema, test SPA fallback returns HTML for unknown routes, test missing static assets returns fallback HTML message

### Implementation for User Story 1

- [x] T017 [US1] Create `ziran/interfaces/web/app.py` — `create_app(dev: bool = False)` factory: include API router at `/api`, mount `StaticFiles` for `static/` directory (if exists), add SPA fallback catch-all route returning `index.html` (or fallback HTML if missing), add CORS middleware when `dev=True`, run Alembic `upgrade("head")` in lifespan handler, configure programmatic Alembic `Config` pointing to `migrations/` directory
- [x] T018 [US1] Add `ziran ui` CLI command to `ziran/interfaces/cli/main.py` — Click command with `--host` (default 127.0.0.1), `--port` (default 8484), `--dev` flag. Guard imports with try/except ImportError showing `pip install ziran[ui]` message. Print banner with URL. Run `uvicorn.run(app, host=host, port=port, reload=dev)`

**Checkpoint**: User Story 1 complete — `ziran ui` starts server, health check works, SPA fallback serves HTML

---

## Phase 4: User Story 4 — Database Schema Management (Priority: P1) MVP

**Goal**: When the server starts, Alembic migrations apply automatically. Fresh databases get all tables; upgraded installs get new migrations without data loss.

**Independent Test**: Start server against empty DB — tables are created. Stop, add a test record, restart — data persists. Verify via `/api/health` database status.

### Tests for User Story 4

- [x] T019 [P] [US4] Add migration tests to `tests/integration/test_web_app.py` — test that `create_app()` lifespan runs migrations on fresh DB, test that health endpoint reports `database: "connected"` after successful migration, test that health endpoint reports `database: "disconnected"` when DB is unreachable

### Implementation for User Story 4

- [x] T020 [US4] Verify Alembic migration runs on startup in `ziran/interfaces/web/app.py` lifespan — ensure `alembic.command.upgrade(config, "head")` executes successfully, add error handling for connection failures with clear error messages per contracts/cli.md

**Checkpoint**: User Story 4 complete — migrations auto-apply, DB connectivity verified via health endpoint

---

## Phase 5: User Story 2 — Developer Frontend Workflow (Priority: P2)

**Goal**: A developer runs the frontend dev server with HMR alongside the backend, edits components, and sees changes instantly.

**Independent Test**: Run `cd ui && npm run dev` and `ziran ui --dev` in parallel. Edit a component — browser updates within 2 seconds. API calls from frontend reach backend via proxy.

### Implementation for User Story 2

- [x] T021 [US2] Initialize `ui/` with Vite + React 18 + TypeScript — run `npm create vite@latest . -- --template react-ts` in `ui/`, configure `tsconfig.json` with strict mode
- [x] T022 [US2] Configure `ui/vite.config.ts` — set `build.outDir` to `../ziran/interfaces/web/static/`, set `build.emptyOutDir` to `true`, add dev server proxy: `/api` → `http://localhost:8484`, `/ws` → `ws://localhost:8484` (ws: true)
- [x] T023 [US2] Install and configure Tailwind CSS in `ui/` — install `tailwindcss`, `postcss`, `autoprefixer`, create `tailwind.config.ts` with TaoQ branding (teal accent `#4fd1c5`, DM Sans font, `darkMode: "class"`), create `src/index.css` with Tailwind directives
- [x] T024 [US2] Install and configure shadcn/ui in `ui/` — install `clsx`, `tailwind-merge`, `lucide-react`, `class-variance-authority`, create `ui/components.json` config, create `ui/src/lib/utils.ts` with `cn()` utility, add initial shadcn/ui components (Button, Card, Badge) via copy-paste pattern
- [x] T025 [US2] Create `ui/src/App.tsx` — React Router v6 setup with routes: `/` → Dashboard, `/runs/new` → NewRun, `/runs/:id` → RunDetail, `/library` → Library, `/settings` → Settings. Wrap with `QueryClientProvider` from TanStack Query.
- [x] T026 [P] [US2] Create layout components — `ui/src/components/layout/Layout.tsx` (sidebar + main content area with dark background), `ui/src/components/layout/Sidebar.tsx` (navigation links with lucide-react icons: LayoutDashboard, Plus, BookOpen, Settings), `ui/src/components/layout/Header.tsx` (page title display)
- [x] T027 [P] [US2] Create placeholder pages — `ui/src/pages/Dashboard.tsx` (empty state with "No scans yet" message and stats placeholder cards), `ui/src/pages/NewRun.tsx` (placeholder), `ui/src/pages/RunDetail.tsx` (placeholder), `ui/src/pages/Library.tsx` (placeholder), `ui/src/pages/Settings.tsx` (placeholder)
- [x] T028 [US2] Create `ui/src/api/client.ts` — base fetch wrapper with `API_BASE` defaulting to `""` (same-origin), typed `get<T>()` and `post<T>()` functions with error handling
- [x] T029 [US2] Create `ui/src/types/index.ts` — TypeScript types mirroring Pydantic schemas: `HealthResponse`, `RunSummary`, `RunStatus`, `PhaseResult`, `ConfigPreset`
- [x] T030 [US2] Create `ui/src/main.tsx` — React entry point, import `index.css`, render `App` with `StrictMode`

**Checkpoint**: User Story 2 complete — `npm run dev` starts with HMR, API proxy works, layout renders with navigation

---

## Phase 6: User Story 3 — PyPI Distribution with Bundled Frontend (Priority: P2)

**Goal**: The Python wheel includes pre-built frontend assets. End users run `pip install ziran[ui]` and `ziran ui` serves the dashboard without Node.js.

**Independent Test**: Run `cd ui && npm run build`, then `uv build`. Install the wheel in a clean venv (no Node.js). Run `ziran ui` — dashboard loads.

### Implementation for User Story 3

- [x] T031 [US3] Create `hatch_build.py` at repo root — custom hatch build hook that checks for Node.js (`shutil.which("node")`), runs `npm ci && npm run build` in `ui/`, skips gracefully if Node.js absent (log warning, continue). Hook class extends `hatchling.builders.hooks.plugin.interface.BuildHookInterface`.
- [x] T032 [US3] Update `pyproject.toml` — add `[tool.hatch.build.hooks.custom]` with `path = "hatch_build.py"`, ensure `[tool.hatch.build.targets.wheel]` has `packages = ["ziran"]`
- [x] T033 [US3] Add Node.js setup and frontend build step to `.github/workflows/release.yml` build job — add `actions/setup-node@v4` (node 20, cache npm, cache-dependency-path `ui/package-lock.json`), add `cd ui && npm ci && npm run build` step before `uv build`
- [x] T034 [US3] N/A — CI workflow does not build wheels; hatch build hook handles frontend compilation during `uv build` (if exists) or main CI workflow — ensure lint/test jobs still work, add frontend build step before package build

**Checkpoint**: User Story 3 complete — `uv build` produces wheel with static assets, CI builds frontend before packaging

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Quality gates and final validation

- [x] T035 Run `uv run ruff check .` and fix any lint violations in new Python files
- [x] T036 Run `uv run ruff format .` and fix any formatting issues in new Python files
- [x] T037 Run `uv run mypy ziran/` and fix any type errors in new Python files (strict mode)
- [x] T038 Run `uv run pytest --cov=ziran` and verify all tests pass with coverage >= 85%
- [x] T039 Validate quickstart.md — follow the end-user and developer workflows manually, verify they work as documented

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 completion — BLOCKS all user stories
- **User Story 1 (Phase 3)**: Depends on Phase 2 — app factory and CLI command
- **User Story 4 (Phase 4)**: Depends on Phase 3 — migration verification (app.py lifespan already written in US1)
- **User Story 2 (Phase 5)**: Depends on Phase 2 — frontend scaffold (can run in parallel with US1/US4)
- **User Story 3 (Phase 6)**: Depends on Phase 5 — needs built frontend to bundle
- **Polish (Phase 7)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Depends on Foundational only — delivers the backend MVP
- **User Story 4 (P1)**: Depends on US1 — verifies migration behavior in the app created by US1
- **User Story 2 (P2)**: Depends on Foundational only — can start in parallel with US1
- **User Story 3 (P2)**: Depends on US2 (needs frontend build output) — must be last before polish

### Within Each User Story

- Tests written first, verify they define the right expectations
- Models/config before services
- Services before routes
- Routes before CLI integration
- Core implementation before error handling

### Parallel Opportunities

- T001–T004 (Setup): T003 can run in parallel with T001/T002
- T005–T012 (Foundational): T005, T006, T007, T008 can all run in parallel (different files)
- T013–T016 (US1 tests): All four test files can run in parallel
- T021–T030 (US2): T026 and T027 can run in parallel (layout vs pages)
- US1 (Phase 3) and US2 (Phase 5) can start in parallel after Foundational completes

---

## Parallel Example: Foundational Phase

```bash
# These tasks touch different files and can run in parallel:
T005: "Create WebUIConfig in ziran/interfaces/web/config.py"
T006: "Create SQLAlchemy models in ziran/interfaces/web/models.py"
T007: "Create Pydantic schemas in ziran/interfaces/web/schemas.py"
T008: "Create DI dependencies in ziran/interfaces/web/dependencies.py"
```

## Parallel Example: User Story 2 (Frontend)

```bash
# After App.tsx is created, these can run in parallel:
T026: "Create layout components in ui/src/components/layout/"
T027: "Create placeholder pages in ui/src/pages/"
```

---

## Implementation Strategy

### MVP First (User Stories 1 + 4 Only)

1. Complete Phase 1: Setup (T001–T004)
2. Complete Phase 2: Foundational (T005–T012)
3. Complete Phase 3: User Story 1 — backend + CLI (T013–T018)
4. Complete Phase 4: User Story 4 — migration verification (T019–T020)
5. **STOP and VALIDATE**: `ziran ui` starts, health check works, migrations apply
6. Deploy/demo if ready

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. Add User Story 1 + 4 → Backend MVP with DB migrations
3. Add User Story 2 → Frontend dev workflow with HMR
4. Add User Story 3 → PyPI bundling, ready for release
5. Polish → Quality gates pass, quickstart validated

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Frontend (ui/) is excluded from Python linting (ruff, mypy)
- All SQLAlchemy models use async patterns (asyncpg)
- All new Python code must have type annotations (mypy strict)
