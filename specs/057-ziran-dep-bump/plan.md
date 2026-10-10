# Implementation Plan: bump multidict and langgraph-sdk to clear two pip-audit CVEs

**Branch**: `ziran-dep-bump` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
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

## Technical context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary dependencies**: uv (lock), pip-audit via `uvx` (audit). No new dependency.
**Storage**: N/A
**Testing**: pytest; CI installs with `uv sync --frozen --group test --extra all`
(`.github/workflows/test.yml`), so the LangGraph and websockets code paths are installed.
**Project type**: single Python package; this change touches `uv.lock` only.

## Why each package moves

| Package | From | To | Reason |
|---|---|---|---|
| multidict | 6.7.1 | 6.9.1 | CVE-2026-104874, fixed in 6.9.1 |
| langgraph-sdk | 0.3.15 | 0.4.6 | CVE-2026-104873, fixed in 0.4.4; `--upgrade-package` takes the highest 0.4.x |
| langgraph | 1.2.2 | 1.2.4 | 1.2.2 requires `langgraph-sdk<0.4.0`; 1.2.3 is yanked; 1.2.4 requires `langgraph-sdk<0.5.0,>=0.4.2` |
| websockets | 17.1 | 16.1.1 | every langgraph-sdk 0.4.x requires `websockets<17` |

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

## Project structure
```text
specs/057-ziran-dep-bump/   spec.md, plan.md, tasks.md, analysis.md, checklists/
uv.lock                     the only non-spec file changed
```

## Complexity tracking
None.
