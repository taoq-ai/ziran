# Implementation Plan: bump multidict, langgraph-sdk and source-map-js to clear the dependency audit

**Branch**: `ziran-dep-bump`, then `ziran-audit-green` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ b813e4f

## Summary
Regenerate `uv.lock` with targeted upgrades so pip-audit passes. The brief's command does not
move langgraph-sdk because locked langgraph 1.2.2 caps it below 0.4, so langgraph is upgraded to
the lowest non-yanked release that admits 0.4.x. One command:

```bash
uv lock --upgrade-package multidict --upgrade-package langgraph-sdk --upgrade-package langgraph==1.2.4
```

Probe result in a detached scratch copy at b813e4f: multidict 6.7.1 -> 6.9.1, langgraph-sdk
0.3.15 -> 0.4.6, langgraph 1.2.2 -> 1.2.4, websockets 17.1 -> 16.1.1. Nothing else moves.

The job's npm step also fails, on source-map-js 1.2.1. Plain `npm audit fix` in `ui/` (no
`--force`) moves source-map-js 1.2.1 -> 1.2.2 in `ui/package-lock.json` and nothing else.
`ui/package.json` stays unchanged: postcss and @tailwindcss/node already allow `^1.2.1`.

## Technical context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary dependencies**: uv (lock), pip-audit via `uvx` (audit), npm 10 on Node 22 (ui lock and
audit). No new dependency.
**Storage**: N/A
**Testing**: pytest; CI installs with `uv sync --frozen --group test --extra all`
(`.github/workflows/test.yml`), so the LangGraph and websockets code paths are installed.
**Project type**: Python package plus the `ui/` frontend; this change touches `uv.lock` and
`ui/package-lock.json` only.

## Why each package moves

| Package | From | To | Reason |
|---|---|---|---|
| multidict | 6.7.1 | 6.9.1 | CVE-2026-104874, fixed in 6.9.1 |
| langgraph-sdk | 0.3.15 | 0.4.6 | CVE-2026-104873, fixed in 0.4.4; `--upgrade-package` takes the highest 0.4.x |
| langgraph | 1.2.2 | 1.2.4 | 1.2.2 requires `langgraph-sdk<0.4.0`; 1.2.3 is yanked; 1.2.4 requires `langgraph-sdk<0.5.0,>=0.4.2` |
| websockets | 17.1 | 16.1.1 | every langgraph-sdk 0.4.x requires `websockets<17` |
| source-map-js (ui) | 1.2.1 | 1.2.2 | GHSA-68fv-2mgg-jv7q (high), affects 1.0.0 to 1.2.1; `npm audit fix` |

Requirement metadata was read from `https://pypi.org/pypi/<name>/<version>/json` on 2026-10-10.

## Constitution check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | N/A | No source change. |
| II. Type safety | PASS | `mypy ziran/` runs against the new websockets and langgraph stubs. |
| III. Tests | PASS | No behaviour change, so no new test. The red check is the failing audit on b813e4f; green is the same audit on the branch. Existing LangGraph and ws tests cover the moved packages. |
| IV. Async-first | N/A | |
| V. Extensibility | N/A | |
| VI. Simplicity | PASS | Lockfile only. `pyproject.toml` unchanged: no bound blocks the fix. |

## Verification
1. Red: pip-audit on b813e4f exits 1 (recorded in spec.md).
2. Lock: run the command above in the worktree.
3. Diff: package-level comparison of `uv.lock` at b813e4f and HEAD shows the four rows above only.
4. Green: `uv export --frozen --no-emit-project --all-extras --format requirements-txt -o <scratch>`
   then the job's `uvx pip-audit -r <scratch> --no-deps --ignore-vuln ...` (seven ids) exits 0.
5. `uv sync --frozen --group test --extra all`, then LangGraph-focused tests
   (`tests/unit/test_langgraph_adapter.py`, `tests/unit/test_pentest_agent.py`,
   `tests/unit/application/test_factories.py`, `tests/unit/test_ws_handler.py`).
6. Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
   `uv run pytest -m "not integration" --cov=ziran`, `uv run pytest -m integration`.
7. ui red: `npm audit --audit-level=high` in `ui/` on d09ee30 exits 1 (recorded in spec.md).
8. ui fix: `npm audit fix` in `ui/`; the diff shows only the source-map-js entry in
   `ui/package-lock.json`.
9. ui green: `npm audit --audit-level=high` exits 0, then the `frontend-build` job steps
   (`npm ci`, `npm run build`, `npm run lint`) pass.

## Project structure
```text
specs/057-ziran-dep-bump/   spec.md, plan.md, tasks.md, analysis.md, checklists/
uv.lock                     Python lock (multidict, langgraph-sdk, langgraph, websockets)
ui/package-lock.json        ui lock (source-map-js)
```

## Complexity tracking
None.
