# Tasks: one sticky Benchmark Coverage comment per PR

Base: `origin/develop` @ 3e7eb6b. Branch `ci/080-benchmark-sticky-comment`. Test first: T001
runs red before T002 and T003.

## Phase 1 - Tests (FR-001 to FR-006)

- [x] T001 Failing unit tests in `tests/unit/test_benchmark_regression.py`: the written comment
      starts with the marker, contains `## Benchmark Coverage Report` and holds no log line (real
      metrics, in a subprocess so the library logs as in CI); a regression still writes the
      comment with the list and exits 1; the delta note follows `--delta-baseline`; the jq
      selector edits only the bot marker comment; only the comment job holds
      `pull-requests: write`, and it has no checkout and no `uv`.

## Phase 2 - Implementation

- [x] T002 `--comment PATH` and `COMMENT_MARKER` in `benchmarks/regression_check.py`.
- [x] T003 Rework `.github/workflows/benchmark.yml` to the plan's workflow shape.
- [x] T004 Check the workflow: YAML parse, `bash -n` on every `run:` script, `actionlint` if
      allowed.

## Phase 3 - Gates and proof

- [x] T005 `uv run ruff check .`, `uv run ruff format --check .`, the touched test file under
      `timeout 120`; the full suite comes from CI.
- [x] T006 Open the draft PR; push a second commit; confirm one marker comment, edited in place,
      with the second head SHA.
