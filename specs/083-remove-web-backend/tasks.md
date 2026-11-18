# Tasks: remove the web backend, the `ui` extra and `ziran ui`

Base: `origin/develop` @ c7da589. Branch `chore/083-remove-web-backend`. Test first: T001 and
T002 run red before T003 and T007.

## Phase 1 - Fix before removing (US1)

- [x] T001 `tests/unit/test_ws_handler.py`: the `streaming` extra requires
      `websockets>=12.0,<18`, `all` lists `streaming` and not `ui`; with `websockets` installed,
      `_ensure_connected` calls `websockets.connect` with the `ws` URL.
- [x] T002 `tests/unit/test_cli_smoke.py`: `ziran ui` (bare and with old flags) prints the moved
      notice and exits 2; `ziran --help` does not list `ui`.
- [x] T003 `pyproject.toml`: add the `streaming` extra and list it in `all`; fix the
      `ws_handler.py` docstring.
- [x] T004 `tests/unit/test_cicd_suppressions.py`: drop the findings-page parity check, keep and
      strengthen the `ziran ci` side.
- [x] T005 `tests/unit/test_phase_graph_persistence.py`: keep the graph-state assertion only.
- [x] T006 Reword the lockstep comments in `html_report.py` and `graph_style/spec.py`.

## Phase 2 - Remove (US2, US3)

- [x] T007 `main.py`: replace `ui_cmd` with the hidden stub.
- [x] T008 Delete `ziran/interfaces/web/` and the web-only tests named in #522.
- [x] T009 `pyproject.toml`: drop the `ui` extra, `ui` from `all`, the web-only mypy overrides;
      keep `fastapi` and `uvicorn` for the promptfoo integration test in the `test` group.
- [x] T010 `uv lock`.

## Phase 3 - Gates

- [x] T011 The acceptance grep; `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/` (default and dev-only envs); the touched test files under
      `timeout 120`. The full suite and coverage come from CI.
- [x] T012 Open the draft PR to `develop`.
