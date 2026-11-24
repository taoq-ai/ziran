# Tasks: release hygiene before the next tag

Base: `origin/develop` @ dfdbe96. Branch `fix/097-release-hygiene`. Test first: T001 runs red
before T002 to T004.

## Phase 1 - Test

- [x] T001 `tests/unit/test_release_workflow.py`: every `uses:` in `release.yml` is pinned by
      commit with its tag; `ci.yml` `lint` runs `uv lock --check`.

## Phase 2 - Fix (FR-001 to FR-004)

- [x] T002 `pyproject.toml`: the `mcp` extra back to `mcp>=1.30,<2`.
- [x] T003 `ci.yml` `lint`: `uv lock --check` step.
- [x] T004 `release.yml`: pin each tag or branch ref to its commit; quote the `gh api` paths.

## Phase 3 - Proof

- [x] T005 `uv lock --check` in `git archive` copies of dfdbe96 (fails) and the head (passes);
      each pinned commit checked with `gh api`; `actionlint` on both workflows.
