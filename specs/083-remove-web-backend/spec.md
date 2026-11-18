# Feature Specification: remove the web backend, the `ui` extra and `ziran ui`

**Feature Branch**: `chore/083-remove-web-backend`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: UI-522-BACKEND (goal G-6), GitHub issue #522, part of #520.
**Base**: `develop` @ c7da589.

## The promise in our own words

The owner decided (#520) that the web UI leaves the open ziran package and continues in ZIRAN
Cloud and ZIRAN Enterprise. This item removes the Python half: the FastAPI backend under
`ziran/interfaces/web/`, the `ui` extra, the web-only mypy overrides and tests, and the working
`ziran ui` command. The React frontend, `hatch_build.py`, the Dockerfile and the Node CI steps
belong to #521; README and docs belong to #523.

Two things the UI removal would break are fixed first:

1. `websockets` is declared only in the `ui` extra, yet the WebSocket target adapter
   (`ws_handler.py`) imports it and tells users to `pip install ziran[streaming]`, an extra that
   does not exist. A new `streaming` extra (`websockets>=12.0,<18`) joins `all`, and the
   `websockets.*` mypy override stays.
2. Two non-web tests import web code. `test_cicd_suppressions.py` keeps its `ziran ci`
   fingerprint checks and drops the parity check against the findings page.
   `test_phase_graph_persistence.py` keeps the assertion on the graph state ziran itself produces
   and drops the database row and schema parts.

The comments in `html_report.py` and `graph_style/spec.py` that promise lockstep with the web
UI's `graphMapping.ts` are reworded: `graph_style.json` is the published styling spec for the
knowledge graph, and other renderers read it from the installed package.

For one minor release `ziran ui` stays as a hidden command. It prints that the UI moved to ZIRAN
Cloud and ZIRAN Enterprise (info@taoq.ai), that ziran v0.42.0 and earlier still ship it under
Apache-2.0, and exits with code 2.

This is a breaking change (a SemVer major for the public CLI and the `ui` extra), announced by
the #520 release note. The next release waits for #521, #522 and #523 together.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - WebSocket targets keep working without the UI (Priority: P1)

**Acceptance Scenarios**:

1. **Given** the package metadata, **When** the `streaming` extra is read, **Then** it requires
   `websockets>=12.0,<18`, and `all` includes `streaming` and no longer includes `ui`.
2. **Given** `websockets` is installed (as `ziran[streaming]` installs it), **When** the
   WebSocket handler connects, **Then** it calls `websockets.connect` with the target's `ws` URL.

### User Story 2 - `ziran ui` tells the user where the UI went (Priority: P1)

1. **Given** the CLI, **When** `ziran ui` runs (with or without its old flags), **Then** it
   prints the moved notice naming ZIRAN Cloud, ZIRAN Enterprise, info@taoq.ai and v0.42.0 under
   Apache-2.0, and exits 2.
2. **Given** the CLI, **When** `ziran --help` runs, **Then** `ui` is not listed.

### User Story 3 - No web code is left in the package (Priority: P1)

1. **Given** the PR head, **When** `grep -rn "interfaces.web\|ziran\[ui\]" ziran tests
   pyproject.toml` runs, **Then** it returns nothing.
2. **Given** CI, **When** ruff, ruff format, mypy strict and pytest with coverage run, **Then**
   all pass.

### Edge Cases

- Old scripts call `ziran ui --host 0.0.0.0 --port 8484 --dev`. The stub accepts and ignores any
  arguments, so they get the notice and exit 2, not a Click usage error.
- `pip install ziran[ui]` on the new release: pip warns that the extra does not exist and
  installs ziran without it. That is pip's behaviour, and the release note covers it.

## Requirements *(mandatory)*

- **FR-001**: `pyproject.toml` MUST declare `streaming = ["websockets>=12.0,<18"]` and list
  `streaming` in `all`.
- **FR-002**: `ziran/interfaces/web/` MUST be deleted in full, with the `ui` extra and `ui` in
  `all`.
- **FR-003**: The mypy overrides for `fastapi.*`, `uvicorn.*`, `sqlalchemy.*`, `asyncpg.*`,
  `alembic.*`, `starlette.*` and the `ziran.interfaces.web.*` block MUST go; `websockets.*` MUST
  stay.
- **FR-004**: `ziran ui` MUST be a hidden command that prints the moved notice and exits 2.
- **FR-005**: The web-only tests named in #522 MUST be deleted; the `ziran ci` and graph-state
  assertions MUST stay.
- **FR-006**: `uv.lock` MUST be regenerated with `uv lock`.

## Success Criteria

- **SC-001**: The acceptance grep returns nothing.
- **SC-002**: The touched test files pass locally; the full suite and coverage pass in CI.

## Assumptions

- `starlette.*` also leaves the mypy overrides. #522 does not name it, but only
  `ziran/interfaces/web/app.py` imported starlette, and mypy then reports the section unused.
  Overturn: ziran code imports starlette again.
- `fastapi` and `uvicorn` move to the `test` dependency group (same ranges as the old `ui`
  extra). `tests/integration/test_promptfoo_integration.py` serves `examples/15` with them and
  would skip silently once the `ui` extra goes. They are dev-only, never installed for users.
  Overturn: that test gets a server that needs neither.
- The `.gitignore` line for `ziran/interfaces/web/static/` stays for #521: the frontend build
  writes there until #521 removes it. Overturn: #521 lands first.
- The stub takes any arguments (`ignore_unknown_options`) so old invocations get the notice.
