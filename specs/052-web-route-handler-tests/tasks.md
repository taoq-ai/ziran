# Tasks: unit tests for the web library and config-preset route handlers

Base: `origin/develop` @ cff8b7f. Work on branch `052-web-route-handler-tests`.

Tests only: the "failing first" step is replaced by a mutation check. Each new test file is first
run against the unchanged handlers (must pass), then a deliberate one-line break in the handler is
made locally, the targeted tests must fail, and the break is reverted (never committed). No
network, no database, no LLM, no API keys. Every test class carries `@pytest.mark.unit`.
Harness, fixture names, stub data and expected values are exactly those in
[plan.md §Public contract](plan.md#public-contract). Production files under `ziran/` MUST NOT be
modified.

## Phase 1 - Library route tests (FR-001, FR-003)

- [X] T001 Create `tests/unit/test_library_api.py` per plan §1: module docstring, `_vector`,
      `VECTORS` (three stub vectors), `client` fixture (monkeypatched `get_attack_library`, bare
      `FastAPI()` at `/api/library`, `TestClient` without context manager), `TestListVectors`
      (no filter, parametrised single filters, search by name / description / tag / upper-case
      term, two combined cases, no-match, summary shape), `TestGetVector` (found with prompts,
      unknown -> 404 + detail), `TestLibraryStats` (exact dict).
- [X] T002 Run `uv run pytest tests/unit/test_library_api.py -v`; all pass.
- [ ] T003 (NOT RUN: editing production code for the local mutation was refused by the implementer's sandbox permission policy; unverified) Mutation check (local only, reverted): in `library.list_vectors` drop `.lower()` from
      the `search` term -> the upper-case search case fails; in `library.get_vector` replace
      `if not vector:` with `if False:` -> the unknown-id 404 test fails (the handler then raises
      `AttributeError`). Revert; `git diff -- ziran/` is empty.

## Phase 2 - Config preset route tests (FR-002, FR-003)

- [X] T004 Create `tests/unit/test_configs_api.py` per plan §2: module docstring, `T0`, `_preset`,
      `_fill_server_defaults`, `db` and `client` fixtures (`get_db` overridden, bare `FastAPI()`
      at `/api`, `TestClient` without context manager), `TestListConfigs`, `TestCreateConfig`
      (201, 409, 422 missing name), `TestUpdateConfig` (config-only mapping to `config_json`,
      name + description only, 404, non-UUID 422), `TestDeleteConfig` (204, 404, non-UUID 422),
      with the call assertions listed in the plan.
- [X] T005 Run `uv run pytest tests/unit/test_configs_api.py -v`; all pass.
- [ ] T006 (NOT RUN: editing production code for the local mutation was refused by the implementer's sandbox permission policy; unverified) Mutation check (local only, reverted): remove the `config` -> `config_json` mapping in
      `update_config` -> the config-only update test fails; remove the 409 branch in
      `create_config` -> the duplicate test fails. Revert; `git diff -- ziran/` is empty.

## Phase 3 - Spec bookkeeping and gates (FR-004, FR-005, FR-006)

- [X] T007 Edit `specs/archive/010-ui-polish-pages/tasks.md`: replace the T035 line exactly as in
      plan §3 (tick it, drop the NOT DONE note, point to spec 052 / #368).
- [X] T008 Coverage of the targets (SC-002): `uv run pytest tests/unit/test_library_api.py
      tests/unit/test_configs_api.py --cov=ziran.interfaces.web.routes.library
      --cov=ziran.interfaces.web.routes.configs --cov-report=term-missing`; both modules at 100%
      (record the actual output in the PR body; if below 100%, add the missing case or report the
      gap, do not claim it).
- [X] T009 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). `git diff --stat origin/develop -- ziran/` empty;
      do not commit `uv.lock` drift.
- [X] T010 Commit `test(web): add library and config preset route handler tests`, push, open the
      PR against `develop` closing #368, with the follow-up from plan §Follow-ups in the body.

## Dependencies
- T001 -> T002 -> T003; T004 -> T005 -> T006; Phases 1 and 2 are independent ([P]).
- T007 any time; T008 after T002 and T005; T009 after all; T010 last.
