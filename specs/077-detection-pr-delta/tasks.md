# Tasks: detection-accuracy PR comment and recall gate

Base: `origin/develop` @ ede6cc6. Branch `ci/077-detection-pr-delta`. Test first: T001 runs red
before T002.

## Phase 1 - Gate and renderer (FR-003, FR-004, FR-005; US2, US1.3)

- [x] T001 Failing unit tests in `tests/unit/test_detection_regression_gate.py`: one lost
      detection (77/0/1/150) fails and names pipeline recall; one added false positive
      (78/1/0/149) fails and names pipeline FPR; an old baseline without the new keys loads and
      gates on F1 only; the renderer shows head and base cells, deltas and the marker; an
      unreadable `--base-result` falls back to the baseline.
- [x] T002 Implement the plan's public contract in `benchmarks/detection_regression.py`.
- [x] T003 Regenerate `benchmarks/results/detection_accuracy_baseline.json` with
      `--update-baseline`; confirm the numbers equal the old file's.

## Phase 2 - Workflow (FR-001, FR-002, FR-006, FR-007; US1, US3)

- [x] T004 Edit `.github/workflows/detection-accuracy.yml`: widen the filter, add the base step,
      the gate flags, the artifact upload and the comment job; move `github.*` values in `run:`
      scripts to `env`.
- [x] T005 Check the workflow: YAML parse plus `bash -n` on every `run:` script (`actionlint`
      was refused in the builder sandbox; CI's own run is the end-to-end check); local dry run of
      the base step against a `git archive` of `origin/develop`, then the gate with `--comment`
      and `--base-result`.

## Phase 3 - Docs and gates

- [x] T006 One paragraph in `docs/reference/benchmarks/detection-accuracy.md` (Regression gate).
- [x] T007 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran`.
- [x] T008 Open the draft PR; confirm its own run posts the comment.
