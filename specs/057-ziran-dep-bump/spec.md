# Feature Specification: bump multidict, langgraph-sdk and source-map-js to clear the dependency audit

**Feature Branch**: `ziran-dep-bump`, carried forward on `ziran-audit-green` (adds the ui lockfile fix)
**Created**: 2026-10-10
**Status**: Active
**Track**: SLICE (lockfiles only; no contract, schema or source change)
**Base**: `develop` @ b813e4f.
**Input**: the `dependency-audit` job in `.github/workflows/ci.yml` fails on develop's `uv.lock`.
Its pip-audit step, run locally on b813e4f, exits 1 with:

```text
Found 2 known vulnerabilities, ignored 8 in 2 packages
Name          Version ID              Fix Versions
------------- ------- --------------- ------------
multidict     6.7.1   CVE-2026-104874 6.9.1
langgraph-sdk 0.3.15  CVE-2026-104873 0.4.4
```

Its npm step (`npm audit --audit-level=high` in `ui/`) also exits 1 on d09ee30 (the first fix):

```text
source-map-js  1.0.0 - 1.2.1
Severity: high
source-map-js allows event-loop denial of service through indexed source-map section offsets - https://github.com/advisories/GHSA-68fv-2mgg-jv7q
fix available via `npm audit fix`
```

source-map-js 1.2.1 comes in through vite 8.2.2 > postcss 8.5.26 and
@tailwindcss/vite 4.3.3 > @tailwindcss/node 4.3.3. The job is green only when both steps pass,
so one branch carries both fixes.

## Clarifications

### Session 2026-10-10
- Q: Which langgraph-sdk fix does the owner want: bump or risk acceptance? A: bump both packages
  in a separate PR to develop (owner decision 2026-10-10, in the brief).
- No other ambiguity left; open two-way choices are under Assumptions.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The dependency audit passes again (Priority: P1)

A contributor opens a PR against develop and the `dependency-audit` job is green, so a red
audit no longer hides new advisories.

**Independent Test**: run every step of the job on the branch head: `uv export --frozen
--no-emit-project --all-extras --format requirements-txt`, then `uvx pip-audit -r ... --no-deps`
with the job's seven `--ignore-vuln` flags, then `npm audit --audit-level=high` in `ui/`. Each
exits 0.

**Acceptance Scenarios**:
1. **Given** the branch `uv.lock`, **When** the pip-audit command runs, **Then** it reports no
   known vulnerability and exits 0.
2. **Given** the branch `uv.lock`, **Then** multidict is at 6.9.1 or later and langgraph-sdk is at
   0.4.4 or later.
3. **Given** the branch `ui/package-lock.json`, **When** `npm audit --audit-level=high` runs in
   `ui/`, **Then** it exits 0 and source-map-js is at 1.2.2.

### User Story 2 - Nothing else moves (Priority: P1)

A reviewer reads the lockfile diff and sees only the two fixed packages and the packages the
resolver must move to admit them.

**Independent Test**: a package-level comparison of `uv.lock` at b813e4f and at the branch head
(name and version of every `[[package]]` entry).

**Acceptance Scenarios**:
1. **Given** the comparison, **Then** the only version changes are multidict, langgraph-sdk,
   langgraph and websockets, each with the reason given under Requirements.
2. **Given** `pyproject.toml`, **Then** it is unchanged.

### User Story 3 - LangGraph scanning still works (Priority: P1)

langgraph-sdk moves from 0.3 to 0.4 and langgraph from 1.2.2 to 1.2.4. A user scanning a
LangGraph agent sees the same behaviour.

**Independent Test**: `uv run pytest tests/unit/test_langgraph_adapter.py
tests/unit/test_pentest_agent.py tests/unit/application/test_factories.py` and the offline
integration tier, then the full gates.

**Acceptance Scenarios**:
1. **Given** the upgraded environment (`uv sync --frozen --group test --extra all`), **Then** the
   LangGraph adapter tests and the full non-integration suite pass with coverage at or above the
   configured floor.
2. **Given** websockets moves 17.1 to 16.1.1, **Then** `tests/unit/test_ws_handler.py` passes and
   `mypy ziran/` accepts `from websockets import ClientConnection`.

### Edge cases
- langgraph 1.2.2 (locked) requires `langgraph-sdk<0.4.0,>=0.3.0`, so the brief's command
  `uv lock --upgrade-package multidict --upgrade-package langgraph-sdk` leaves langgraph-sdk at
  0.3.15 (verified in a scratch copy: it only updates multidict). langgraph must move too.
- Every langgraph-sdk 0.4.x release on PyPI (0.4.0 to 0.4.6) requires `websockets<17,>=14`
  (0.4.0 to 0.4.2: `<16`). The lock has websockets 17.1, so the resolver must take websockets
  down to 16.1.1. ziran's own bound (`websockets>=12.0,<18` in the `ui` and `all` extras) admits
  16.1.1, so `pyproject.toml` needs no change.
- langgraph 1.2.3 is yanked on PyPI ("unintended merging strategy regression").

## Requirements *(mandatory)*

### Functional requirements
- **FR-001**: `uv.lock` pins multidict 6.9.1 (fixes CVE-2026-104874).
- **FR-002**: `uv.lock` pins langgraph-sdk 0.4.6, the highest 0.4.x release, which
  `--upgrade-package langgraph-sdk` selects (fixes CVE-2026-104873, fixed in 0.4.4).
- **FR-003**: `uv.lock` pins langgraph 1.2.4, the lowest non-yanked release whose metadata admits
  langgraph-sdk 0.4.x (`langgraph-sdk<0.5.0,>=0.4.2`). It needs `langchain-core>=1.4.0`; the lock
  already has 1.4.8.
- **FR-004**: `uv.lock` pins websockets 16.1.1, forced by langgraph-sdk 0.4.x's `websockets<17`.
- **FR-005**: no other `[[package]]` entry changes version, no `pyproject.toml` change, no source
  change. In `ui/package-lock.json` only source-map-js moves (1.2.1 to 1.2.2, via plain
  `npm audit fix`, fixes GHSA-68fv-2mgg-jv7q); `ui/package.json` and the CI workflow are unchanged.
- **FR-006**: every step of the `dependency-audit` job exits 0 on the branch: the export, the
  pip-audit command with the existing `--ignore-vuln` list unchanged, and the npm audit step.

### Assumptions
- **langgraph version: lowest compatible, not latest.** Assumed 1.2.4 (via
  `--upgrade-package langgraph==1.2.4`) because the brief asks to keep every other version as close
  as the fix allows. 1.2.3 is yanked. Overturned if the gates fail on 1.2.4 but pass on a later
  1.2.x, or if the owner prefers the latest patch (1.2.14, which would also need
  `langgraph-sdk>=0.4.6`, already met).
- **langgraph-sdk version: 0.4.6, not 0.4.4.** The brief's command `--upgrade-package
  langgraph-sdk` selects the highest allowed release; kept as is. Overturned if 0.4.6 breaks a
  gate that 0.4.4 passes.
- **websockets downgrade accepted.** 17.1 to 16.1.1 is forced by every langgraph-sdk 0.4.x. ziran
  uses `websockets.connect` and `websockets.ClientConnection` only
  (`ziran/infrastructure/adapters/protocols/ws_handler.py`), both present in 16.x. Overturned if
  pip-audit flags 16.1.1 or the ws tests fail.
- **One spec for both fixes.** The ui lockfile fix (item ZIRAN-AUDIT-GREEN) amends this spec
  instead of opening a new directory, because the two fixes ship in one PR for one CI job.
  Overturned if a reviewer wants a separate spec per lockfile.
- **Spec directory name.** The brief names `specs/057-dep-bump-cves/`; the spec tooling
  looks for `specs/*-ziran-dep-bump`, so the directory is `specs/057-ziran-dep-bump/`. Number 057
  is kept. Overturned by a reviewer who wants the brief's name; renaming is a one-line move.

## Success criteria *(mandatory)*

- **SC-001**: every step of the `dependency-audit` job in `.github/workflows/ci.yml` exits 0 on the
  branch (pip-audit exits 1 on b813e4f and npm audit exits 1 on d09ee30, output above).
- **SC-002**: the package-level lock comparison lists exactly the four version changes in
  FR-001 to FR-004.
- **SC-003**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest -m "not integration" --cov=ziran` and `uv run pytest -m integration` pass.
- **SC-004**: the `frontend-build` job steps pass in `ui/` with Node 22: `npm ci`,
  `npm run build`, `npm run lint`.
