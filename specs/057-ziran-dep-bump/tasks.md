# Tasks: bump multidict, langgraph-sdk and source-map-js to clear the dependency audit

Base: `develop` @ b813e4f. Branch `ziran-dep-bump`. Commands and package table are in
[plan.md](plan.md).

## Phase 1 - Red

- [x] T001 Run the `dependency-audit` pip-audit command on b813e4f's lockfile and record the
      failure (multidict CVE-2026-104874, langgraph-sdk CVE-2026-104873).

## Phase 2 - Lock (FR-001 to FR-005)

- [x] T002 Run `uv lock --upgrade-package multidict --upgrade-package langgraph-sdk
      --upgrade-package langgraph==1.2.4` in the worktree.
- [x] T003 Package-level comparison of `uv.lock` against b813e4f: only multidict, langgraph-sdk,
      langgraph and websockets change version; `pyproject.toml` and `ui/package-lock.json` unchanged.

## Phase 3 - Green (FR-006, SC-001)

- [x] T004 Re-export requirements and rerun the pip-audit command; exit 0.

## Phase 4 - Regression (SC-003)

- [x] T005 `uv sync --frozen --group test --extra all`; confirm installed versions match the lock.
- [x] T006 Run the LangGraph and websockets tests named in plan.md step 5.
- [x] T007 Run the full gates from plan.md step 6.

## Phase 5 - Ship

- [x] T008 Commit `fix(deps): bump multidict and langgraph-sdk for CVE-2026-104874 and
      CVE-2026-104873` (no Co-Authored-By trailer); push to `ziran-dep-bump`. No PR.

## Phase 6 - ui lockfile (branch `ziran-audit-green`, fast-forwarded from d09ee30)

- [x] T009 Run `npm audit --audit-level=high` in `ui/` on d09ee30; record the source-map-js
      GHSA-68fv-2mgg-jv7q failure.
- [x] T010 Run `npm audit fix` (no `--force`) in `ui/`; only source-map-js 1.2.1 -> 1.2.2 moves
      in `ui/package-lock.json`; `ui/package.json` unchanged.
- [x] T011 Run every `dependency-audit` step (export, pip-audit, npm audit) and the
      `frontend-build` steps (`npm ci`, `npm run build`, `npm run lint`); each exits 0.
- [x] T012 Rerun the Python gates from plan.md step 6 (non-integration tier).
- [x] T013 Commit `fix(deps): bump source-map-js in ui lockfile for GHSA-68fv-2mgg-jv7q`; push
      to `ziran-audit-green`. No PR.

## Dependencies
T001 -> T002 -> T003 -> T004 -> T005 -> T006 -> T007 -> T008 -> T009 -> T010 -> T011 -> T012
-> T013.
