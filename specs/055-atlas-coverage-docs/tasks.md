# Tasks: honest ATLAS coverage docs for AI Model Access and AI Attack Staging

Base: `origin/develop` @ 7e1ef38. Work on branch `055-atlas-coverage-docs`.

Test-first: the regression assertion lands first and is shown able to fail before the docs change.
Because the criterion is already met on develop, the "red" step is a temporary threshold bump,
reverted before commit. No network, no LLM, no API keys. Exact assertion text, docs content and
the not-changed list are in [plan.md §Public contract](plan.md#public-contract).

## Phase 1 - Regression assertion (FR-007; US3)

- [x] T001 In `tests/integration/test_atlas_coverage_script.py::test_json_output_matches_expected_schema`,
      append the `for tactic in ("AML.TA0000", "AML.TA0001"): assert ... >= 1, tactic` block from
      plan §1 after the `techniques_covered >= 60` assertion.
- [x] T002 Red check: temporarily change `>= 1` to `>= 99`, run
      `uv run pytest tests/integration/test_atlas_coverage_script.py -k expected_schema` and confirm it
      fails on `AML.TA0000`; restore `>= 1`. Keep the failing output line for the PR body.
- [x] T003 Run `uv run pytest tests/integration/test_atlas_coverage_script.py`; all 4 tests pass.

## Phase 2 - Capture real numbers (SC-001)

- [x] T004 Run `uv run python benchmarks/atlas_coverage.py` and
      `uv run python benchmarks/atlas_coverage.py --json <scratchpad>/atlas.json` on the branch
      head. Extract `per_tactic` for `AML.TA0000`/`AML.TA0001` and `per_technique` for every
      technique whose `tactics` contains either id. Diff against the table in plan §2; any
      difference wins over the plan and is noted in the PR body.

## Phase 3 - Docs (FR-001..FR-006; US1, US2)

- [x] T005 [P] Rewrite the body of `## Coverage scope (honest)` in
      `docs/reference/benchmarks/atlas-mapping.md` per plan §2 (intro, per-technique table with T004
      numbers, T0040/T0047 premise paragraph, roll-up double-count sentence, no-staging-vectors
      sentence). Remove the "See issue #264 ..." sentence. Touch nothing else on the page.
- [x] T006 [P] `docs/community/roadmap.md` line 186: `- [ ]` -> `- [x]` on the #264 line.
- [x] T007 Check: `grep -n "issues/264" docs/reference/benchmarks/atlas-mapping.md` is empty;
      `grep -n "#264" docs/community/roadmap.md` shows `- [x]`; the TA0000/TA0001 fractions in the new
      section equal those in `docs/reference/benchmarks/coverage-comparison.md` (3/4, 7/7 at plan time).

## Phase 4 - Gates (FR-008, SC-003, SC-004)

- [x] T008 Run and record real output: `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%). Optionally
      `uvx --with mkdocs-material mkdocs build --strict`; if it cannot run, report it unverified.
- [x] T009 `git diff --stat origin/develop` shows only the three files in plan §Project Structure
      (plus the spec dir and expected `CLAUDE.md` agent-context churn); `uv.lock` unchanged.
- [ ] T010 Commit as `docs(atlas): ...` (no Co-Authored-By trailer). PR against `develop` with: the
      script output lines for TA0000/TA0001, the red-check failure line, the reading of the issue's
      acceptance line (>= 1 technique per tactic), why no staging vectors were added, and the
      follow-ups (regenerate `coverage-comparison.md`; distinct-vector per-tactic counts).

## Dependencies
T001 -> T002 -> T003. T004 before T005. T005/T006 independent of each other. T007 after T005/T006.
T008-T009 after all edits; T010 last.
