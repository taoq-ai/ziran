# Feature Specification: unit tests for the web library and config-preset route handlers

**Feature Branch**: `052-web-route-handler-tests`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #368 (release 0.42.0, "faster scans, truer graphs" batch). Closes spec 010 task T035.
**Base**: `develop` @ cff8b7f.
**Siblings (parallel, separate worktrees)**: #288 / spec 049, #393 / spec 050, #73 / spec 051.
None of them touches the files of this feature.
**Scope**: tests only. Two new test files plus the T035 checkbox in
`specs/archive/010-ui-polish-pages/tasks.md`. No production code changes, no new endpoint, no new
dependency.
**Input**: spec 010 shipped `ziran/interfaces/web/routes/library.py` (`GET /api/library/vectors`,
`GET /api/library/vectors/{vector_id}`, `GET /api/library/stats`) and
`ziran/interfaces/web/routes/configs.py` (`GET/POST /api/configs`,
`PUT/DELETE /api/configs/{preset_id}`) without handler tests. `test_web_schemas.py` and
`test_web_models.py` cover the Pydantic schemas and ORM models only; filtering, 404 paths and
validation errors are untested.

## User Scenarios & Testing *(mandatory)*

Shared fixtures (all offline, defined in each test file; no new shared module):
- **Stub library**: a small object with `vectors: list[AttackVector]` and
  `get_vector(id) -> AttackVector | None`, holding three real `AttackVector` instances that differ
  in category, severity, phase, OWASP mapping, name/description/tags and prompt count. It replaces
  `ziran.interfaces.web.routes.library.get_attack_library` via `monkeypatch`. The bundled vector
  library is never loaded, so no assertion depends on how many vectors ship.
- **Stub session**: a `MagicMock` `AsyncSession` whose `execute` / `get` / `commit` / `refresh` /
  `delete` are `AsyncMock`s returning real `ConfigPreset` instances (id, `created_at`,
  `updated_at` set). It is injected by overriding `ziran.interfaces.web.dependencies.get_db`.
- **App**: a bare `FastAPI()` with the two routers mounted at the same prefixes as `create_app()`
  (`/api` for configs, `/api/library` for library), driven by `fastapi.testclient.TestClient`. The
  real app lifespan (Alembic against PostgreSQL) never runs.

### User Story 1 - Library list filters are pinned (Priority: P1)

A maintainer changes the library route and a test fails if any filter stops working.

**Independent Test**: `tests/unit/test_library_api.py` against the stub library.

**Acceptance Scenarios**:
1. **Given** no query parameters, **When** `GET /api/library/vectors`, **Then** `200`, `total`
   equals the stub's vector count and every stub id is returned.
2. **Given** `?category=<c>`, **Then** only vectors whose `str(category) == c` are returned and
   `total` equals their count. Same for `?severity=`, `?phase=` (matches `target_phase`) and
   `?owasp=` (matches any entry of `owasp_mapping`, e.g. `LLM01`).
3. **Given** `?search=<term>`, **Then** vectors whose name, description or any tag contains the
   term case-insensitively are returned: one case matches only via name, one only via description,
   one only via a tag, and an upper-case term matches lower-case text.
4. **Given** two filters combined (e.g. `?category=<c>&severity=<s>`), **Then** only vectors
   matching both are returned.
5. **Given** a filter value no stub vector has, **Then** `200` with `vectors == []` and
   `total == 0`.

### User Story 2 - Vector detail and stats are pinned (Priority: P1)

**Independent Test**: same file and stub.

**Acceptance Scenarios**:
1. **Given** a known id, **When** `GET /api/library/vectors/{id}`, **Then** `200` with that id and
   a `prompts` list whose length and `template` values match the stub vector.
2. **Given** an unknown id, **Then** `404` with `detail == "Vector not found"`.
3. **Given** the stub library, **When** `GET /api/library/stats`, **Then** `total_vectors`,
   `total_prompts` (sum of `prompt_count`), `by_category`, `by_severity` and `by_owasp` equal
   values computed by hand from the three stub vectors (a vector with two OWASP entries counts in
   both).

### User Story 3 - Config preset CRUD and its errors are pinned (Priority: P1)

**Independent Test**: `tests/unit/test_configs_api.py` with the stub session.

**Acceptance Scenarios**:
1. **Given** the session returns two presets, **When** `GET /api/configs`, **Then** `200` and a
   list of two objects with `id`, `name`, `description`, `config_json`, `created_at`,
   `updated_at`. ("Read" is this list endpoint; there is no `GET /api/configs/{id}`.)
2. **Given** no preset with the name exists, **When** `POST /api/configs` with
   `{"name": "n", "description": "d", "config": {"k": 1}}`, **Then** `201`, the response has
   `name == "n"` and `config_json == {"k": 1}`, and `add`, `commit` and `refresh` were each called
   once.
3. **Given** a preset with that name exists, **When** `POST`, **Then** `409` with
   `detail == "Config preset name already exists"` and `commit` not called.
4. **Given** a body without `name`, **When** `POST`, **Then** `422` and the session is not used.
5. **Given** an existing preset, **When** `PUT /api/configs/{id}` with `{"config": {"z": 2}}`,
   **Then** `200`, `config_json == {"z": 2}` (the `config` field maps to the `config_json`
   column), `name` and `description` unchanged, `updated_at` advanced, `commit` called. A second
   case updates `name` and `description` only and leaves `config_json` unchanged.
6. **Given** `get` returns `None`, **When** `PUT`, **Then** `404` with
   `detail == "Config preset not found"`.
7. **Given** an existing preset, **When** `DELETE /api/configs/{id}`, **Then** `204` with an empty
   body and `delete` + `commit` called with that preset.
8. **Given** `get` returns `None`, **When** `DELETE`, **Then** `404` and `delete` not called.
9. **Given** a non-UUID path segment (`/api/configs/not-a-uuid`), **When** `PUT` or `DELETE`,
   **Then** `422` and the session is not used.

### Edge Cases
- `update_config` does not check name uniqueness: renaming a preset to an existing name makes
  `commit` raise `IntegrityError` (unique constraint on `config_presets.name`), which is unhandled
  and returns `500`. `create_config` has the same gap under a concurrent insert (check then
  insert). Recorded as a follow-up, **not fixed and not tested here** (tests-only scope).
- Filters on the library list are exact string matches with no validation: an unknown
  `category` returns an empty list, not `422` (US1.5 pins this).
- The stub session cannot prove SQL semantics (ordering by `created_at desc`, the unique
  constraint); that needs PostgreSQL and stays out of the unit suite.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: `tests/unit/test_library_api.py` exists and covers US1 and US2: each filter
  dimension (category, severity, phase, owasp, search over name/description/tags,
  case-insensitive), no filter, combined filters, no match, detail found (with prompts), unknown
  id -> 404, and the stats aggregation.
- **FR-002**: `tests/unit/test_configs_api.py` exists and covers US3: list, create (201),
  duplicate name (409), missing name (422), partial update including the `config` ->
  `config_json` mapping, update of a missing id (404), delete (204), delete of a missing id (404),
  non-UUID id (422).
- **FR-003**: every test class or function carries `@pytest.mark.unit`; no test opens a network
  connection, a database, or loads the bundled attack library; no assertion depends on the number
  of bundled vectors.
- **FR-004**: no production file changes (`git diff --stat origin/develop` lists only the two test
  files, `specs/archive/010-ui-polish-pages/tasks.md`, this spec directory and the
  agent-context update to `CLAUDE.md`).
- **FR-005**: T035 in `specs/archive/010-ui-polish-pages/tasks.md` is ticked and its
  "NOT DONE" note replaced by a pointer to this spec.
- **FR-006**: all quality gates pass and overall coverage stays >= 85%.

### Assumptions (recorded, most conservative reading)
- The issue's "read" in CRUD maps to `GET /api/configs` (list); no `GET /api/configs/{id}` is
  added.
- "Validation failures" means FastAPI request validation (`422`: missing required field,
  non-UUID path id) plus the handler's own `409`; no new validation is introduced.
- Tests mount the routers on a bare `FastAPI()` instead of `create_app()` so the lifespan
  (Alembic, PostgreSQL, `RunManager`) is never entered; the routers, prefixes and dependency are
  the production ones.
- `aiosqlite` is not used: `ConfigPreset` uses PostgreSQL `JSONB`/`UUID` column types.
- `fastapi` and `sqlalchemy` come from the `ui` extra; CI installs `--extra all`, as for the
  existing `test_web_models.py`, so no `importorskip` is added.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: `uv run pytest tests/unit/test_library_api.py tests/unit/test_configs_api.py -m unit`
  passes offline.
- **SC-002**: with those two files, `ziran/interfaces/web/routes/library.py` and
  `ziran/interfaces/web/routes/configs.py` reach 100% line coverage
  (`--cov=ziran.interfaces.web.routes.library --cov=ziran.interfaces.web.routes.configs
  --cov-report=term-missing`).
- **SC-003**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest --cov=ziran` (>= 85%) pass.
- **SC-004**: `git diff --stat origin/develop -- ziran/` is empty.

## Follow-ups (not filed by this spec)
- Return `409` instead of `500` when `PUT /api/configs/{id}` renames a preset to an existing name
  (and catch `IntegrityError` on create for the concurrent-insert race).
