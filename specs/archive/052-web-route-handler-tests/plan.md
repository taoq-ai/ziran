# Implementation Plan: unit tests for the web library and config-preset route handlers

**Branch**: `052-web-route-handler-tests` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #368 (release 0.42.0) | **Base**: `develop` @ cff8b7f
**Parallel siblings**: #288 / spec 049, #393 / spec 050, #73 / spec 051. No shared file: this
feature adds two test files and edits one line block of an archived spec's `tasks.md`.

## Summary
Add `tests/unit/test_library_api.py` and `tests/unit/test_configs_api.py`. Both mount the
production routers on a bare `FastAPI()` at the production prefixes and drive them with
`TestClient`. The library tests replace `get_attack_library` (as imported into
`ziran.interfaces.web.routes.library`) with a three-vector stub, so assertions are hand-computed
and independent of the bundled vectors. The configs tests override `get_db` with a mocked
`AsyncSession` returning real `ConfigPreset` rows. Then tick T035 in spec 010. No production code
changes.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: pytest, `fastapi.testclient.TestClient` (fastapi from the `ui` extra), stdlib `unittest.mock`. Tests only, no production change. No new dependencies.
**Storage**: N/A (no database, no files).
**Testing**: `@pytest.mark.unit`; `monkeypatch`; `app.dependency_overrides`. CI runs these in the
`pytest -m "not integration"` job with `--extra all`.
**Target Platform**: `ziran/interfaces/web/routes/library.py`, `ziran/interfaces/web/routes/configs.py`
(read-only targets).
**Project Type**: single Python package.
**Constraints**: do not enter `create_app()`'s lifespan (it runs Alembic against PostgreSQL);
do not use aiosqlite (`JSONB` / `UUID(as_uuid=True)` columns do not compile on SQLite); do not
assert counts of bundled vectors; no network.
**Feasibility check (run, not committed)**: a scratch script with the exact harness below, run with
`uv run python` on this branch's base, returned for the stub library `search=foo` -> 1 match,
unknown id -> 404, stats aggregated correctly, detail returned prompts; and for configs list 200,
create 201 (with a `refresh` side effect filling `id`/timestamps), missing name 422, `config` ->
`config_json` mapping on PUT, non-UUID PUT 422, delete of missing id 404.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | No production code. Tests drive the `interfaces/web` routers through their public HTTP surface; the domain `AttackVector` is used as data. |
| II. Type safety | PASS | No `ziran/` change, so `mypy ziran/` is unaffected; test helpers are annotated anyway. |
| III. Tests | PASS | Adds the missing handler tests; `@pytest.mark.unit` on every class; no DB, no network, stubs only. |
| IV. Async-first | PASS | Handlers stay async; `TestClient` runs them on its own loop; session methods are `AsyncMock`s. |
| V. Extensibility | PASS | Not affected. |
| VI. Simplicity | PASS | Fixtures live in each test file (two files, no shared conftest change); stdlib mocks; no new endpoint, no new helper module. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #368 implementer. Production code is unchanged; the contract below is the test
harness and the HTTP surface under test.

### HTTP surface under test (existing, unchanged)

| Method + path | Handler | Success | Errors |
|---|---|---|---|
| `GET /api/library/vectors?category&severity&phase&owasp&search` | `library.list_vectors` | `200 VectorListResponse{vectors: list[VectorSummary], total: int}` | none (unknown values -> empty list) |
| `GET /api/library/vectors/{vector_id}` | `library.get_vector` | `200 VectorDetail` (VectorSummary + `references`, `prompts: list[PromptTemplate]`) | `404 {"detail": "Vector not found"}` |
| `GET /api/library/stats` | `library.library_stats` | `200 LibraryStatsResponse{total_vectors, total_prompts, by_category, by_severity, by_owasp}` | none |
| `GET /api/configs` | `configs.list_configs` | `200 list[ConfigPresetResponse]` | none |
| `POST /api/configs` body `ConfigPresetCreate{name: str, description: str|None, config: dict}` | `configs.create_config` | `201 ConfigPresetResponse` | `409 {"detail": "Config preset name already exists"}`, `422` (missing `name`) |
| `PUT /api/configs/{preset_id: UUID}` body `ConfigPresetUpdate{name?, description?, config?}` | `configs.update_config` | `200 ConfigPresetResponse` (`config` -> `config_json`) | `404 {"detail": "Config preset not found"}`, `422` (non-UUID id) |
| `DELETE /api/configs/{preset_id: UUID}` | `configs.delete_config` | `204`, empty body | `404 {"detail": "Config preset not found"}`, `422` (non-UUID id) |

`ConfigPresetResponse` fields: `id: UUID`, `name: str`, `description: str | None`,
`config_json: dict[str, Any]`, `created_at: datetime`, `updated_at: datetime`
(`from_attributes=True`, so it reads ORM attributes).

### 1. `tests/unit/test_library_api.py` (new)

```python
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ziran.domain.entities.attack import AttackPrompt, AttackVector
from ziran.interfaces.web.routes import library

def _vector(**overrides: object) -> AttackVector: ...      # defaults + overrides

VECTORS: list[AttackVector]   # exactly the three below, module-level constant

@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    stub = SimpleNamespace(
        vectors=VECTORS,
        get_vector=lambda vid: next((v for v in VECTORS if v.id == vid), None),
    )
    monkeypatch.setattr(library, "get_attack_library", lambda: stub)
    app = FastAPI()
    app.include_router(library.router, prefix="/api/library")
    return TestClient(app)     # NOT used as a context manager (no lifespan needed or wanted)
```

Stub vectors (real `AttackVector` instances; values chosen so each search term hits exactly one
field of exactly one vector):

| id | name | category | severity | target_phase | description | tags | owasp_mapping | prompts |
|---|---|---|---|---|---|---|---|---|
| `v_alpha` | `Alpha Override` | `prompt_injection` | `high` | `reconnaissance` | `Overrides the system prompt` | `["jailbreak"]` | `["LLM01"]` | 2 |
| `v_beta` | `Beta Leak` | `data_exfiltration` | `critical` | `capability_mapping` | `Leaks SECRET tokens` | `["exfil"]` | `["LLM01", "LLM02"]` | 1 |
| `v_gamma` | `Gamma Tool` | `tool_manipulation` | `high` | `reconnaissance` | `Misuses a tool` | `["Unicode-Smuggle"]` | `[]` | 1 |

Test classes (all `@pytest.mark.unit`) and the exact expectations:
- `TestListVectors`
  - no filter -> ids `{v_alpha, v_beta, v_gamma}`, `total == 3`
  - `category=prompt_injection` -> `[v_alpha]`; `severity=high` -> `{v_alpha, v_gamma}`;
    `phase=reconnaissance` -> `{v_alpha, v_gamma}`; `owasp=LLM01` -> `{v_alpha, v_beta}`;
    `owasp=LLM02` -> `[v_beta]` (parametrised over `(params, expected_ids)`); `total ==
    len(expected_ids)` in every case
  - search: `alpha` -> `[v_alpha]` (name), `secret` -> `[v_beta]` (description, case differs),
    `unicode` -> `[v_gamma]` (tag, case differs), `ALPHA` -> `[v_alpha]` (upper-case term)
  - combined: `category=prompt_injection&severity=high` -> `[v_alpha]`;
    `severity=high&search=tool` -> `[v_gamma]`
  - no match: `category=model_dos` -> `vectors == []`, `total == 0`
  - summary shape: the `v_beta` item has `owasp_mapping == ["LLM01", "LLM02"]`,
    `prompt_count == 1`, `target_phase == "capability_mapping"`
- `TestGetVector`
  - `v_alpha` -> `200`, `id == "v_alpha"`, `len(prompts) == 2`, prompt `template` values equal the
    stub's
  - `nope` -> `404`, `json() == {"detail": "Vector not found"}`
- `TestLibraryStats`
  - `json() == {"total_vectors": 3, "total_prompts": 4, "by_category": {"prompt_injection": 1,
    "data_exfiltration": 1, "tool_manipulation": 1}, "by_severity": {"high": 2, "critical": 1},
    "by_owasp": {"LLM01": 2, "LLM02": 1}}`

### 2. `tests/unit/test_configs_api.py` (new)

```python
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import ConfigPreset
from ziran.interfaces.web.routes import configs

T0 = datetime(2026, 1, 1, tzinfo=UTC)

def _preset(name: str = "baseline", **overrides: object) -> ConfigPreset:
    """Real ORM row with id, description, config_json, created_at=T0, updated_at=T0 set."""

@pytest.fixture
def db() -> MagicMock:
    session = MagicMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result)
    session.get = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.delete = AsyncMock()
    session.refresh = AsyncMock(side_effect=_fill_server_defaults)
    return session

async def _fill_server_defaults(obj: ConfigPreset) -> None:
    """Emulate flush defaults: set id / created_at / updated_at when None."""

@pytest.fixture
def client(db: MagicMock) -> TestClient:
    app = FastAPI()
    app.include_router(configs.router, prefix="/api")

    async def _override() -> AsyncGenerator[MagicMock, None]:
        yield db

    app.dependency_overrides[get_db] = _override
    return TestClient(app)     # NOT used as a context manager
```

Why `refresh` needs a side effect: `create_config` builds a transient `ConfigPreset` whose `id`
and timestamps are column defaults applied only at flush; `ConfigPresetResponse.model_validate`
would reject `id=None`.

Test classes (all `@pytest.mark.unit`) and the exact expectations:
- `TestListConfigs`: `scalars().all()` returns two presets -> `200`, two items, names and ids
  match, each item has the six response keys.
- `TestCreateConfig`
  - created: body `{"name": "n", "description": "d", "config": {"k": 1}}` -> `201`,
    `name == "n"`, `description == "d"`, `config_json == {"k": 1}`; `db.add` called once with a
    `ConfigPreset` whose `config_json == {"k": 1}`; `commit` and `refresh` awaited once
  - duplicate: `scalar_one_or_none` returns `_preset("n")` -> `409`,
    `json() == {"detail": "Config preset name already exists"}`; `add` not called, `commit` not
    awaited
  - missing name: body `{"config": {}}` -> `422`; `execute` not awaited
- `TestUpdateConfig`
  - config only: `get` returns `_preset()`; body `{"config": {"z": 2}}` -> `200`,
    `config_json == {"z": 2}`, `name`/`description` unchanged, `updated_at` parses later than
    `T0`; `commit` awaited once; `get` awaited with `(ConfigPreset, <that UUID>)`
  - name + description only: `config_json` unchanged, new `name`/`description` returned
  - missing: `get` returns `None` -> `404`, `json() == {"detail": "Config preset not found"}`;
    `commit` not awaited
  - non-UUID: `PUT /api/configs/not-a-uuid` -> `422`; `get` not awaited
- `TestDeleteConfig`
  - existing: `get` returns a preset -> `204`, `content == b""`; `delete` awaited with that preset;
    `commit` awaited once
  - missing: `get` returns `None` -> `404`; `delete` not awaited
  - non-UUID: `DELETE /api/configs/not-a-uuid` -> `422`; `get` not awaited

### 3. `specs/archive/010-ui-polish-pages/tasks.md` (edit, T035 line only)

Replace the T035 line with:

```markdown
- [X] T035 Create unit tests for library and configs routes in `tests/unit/test_library_api.py` and `tests/unit/test_configs_api.py` (done in spec 052, issue #368)
```

### 4. Output shapes
No new output. Tests assert the existing JSON shapes in the table above.

## Acceptance criteria -> offline proof

| Criterion (issue, narrowed by the brief) | Proven by | Live model / DB? |
|---|---|---|
| `test_library_api.py` covers each filter dimension | `TestListVectors` parametrised filter cases + search cases + combined + no-match (US1.1-US1.5) | No |
| Unknown `vector_id` -> 404 | `TestGetVector` 404 case (US2.2) | No |
| Stats aggregation | `TestLibraryStats` exact dict against the three-vector stub (US2.3) | No |
| `test_configs_api.py` covers create/read/update/delete | `TestCreateConfig`, `TestListConfigs` (read = list), `TestUpdateConfig`, `TestDeleteConfig` (US3.1, 3.2, 3.5, 3.7) | No |
| Validation failures | missing `name` 422, non-UUID 422 (PUT and DELETE), duplicate name 409 (US3.3, 3.4, 3.9) | No |
| Delete of missing -> 404 | `TestDeleteConfig` missing case (US3.8); update-missing 404 too (US3.6) | No |
| Coverage >= 85% overall | `uv run pytest --cov=ziran` gate; SC-002 per-module 100% via `--cov=ziran.interfaces.web.routes.library --cov=ziran.interfaces.web.routes.configs --cov-report=term-missing` on the two files | No |
| No production change | `git diff --stat origin/develop -- ziran/` empty (SC-004) | No |
| SQL semantics (order by `created_at desc`, unique constraint) | not provable with a mocked session | **Needs PostgreSQL: out of scope, not claimed** |

## Project Structure

### Documentation (this feature)
```text
specs/052-web-route-handler-tests/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
tests/unit/test_library_api.py                 # new
tests/unit/test_configs_api.py                 # new
specs/archive/010-ui-polish-pages/tasks.md     # edit: tick T035
```
**Structure Decision**: one test file per router, fixtures local to each file; no conftest change.

## Follow-ups (noted, not filed, out of scope)
- `update_config` has no name-uniqueness check: renaming to an existing name raises
  `IntegrityError` at `commit` -> unhandled `500`. Fix: query by name excluding `preset_id` and
  return `409`, and/or catch `IntegrityError` in both create and update (also covers the
  check-then-insert race in `create_config`).

## Release note for the implementer
Commit as `test(web): add library and config preset route handler tests` (spec tick may ride in
the same commit or as `docs(spec): ...`). No `!`, no `BREAKING CHANGE`, no `Co-Authored-By`.
PR targets `develop`, links #368 (closes it) and notes the follow-up above.

## Phases
- P1: library tests (FR-001, FR-003).
- P2: configs tests (FR-002, FR-003).
- P3: tick T035 (FR-005); gates (FR-004, FR-006). Do not commit `uv.lock` drift.

## Complexity Tracking
None.
