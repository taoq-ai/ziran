# Implementation Plan: one sticky Benchmark Coverage comment per PR

**Branch**: `ci/080-benchmark-sticky-comment` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ 3e7eb6b

## Summary

Add `--comment PATH` to `benchmarks/regression_check.py`, which writes the existing markdown
report behind a marker line and a delta note. In `.github/workflows/benchmark.yml`, collect the
PR base metrics before the gate, run the gate once with `--comment` and `--delta-baseline`,
upload the file, and post it from a second job that alone holds `pull-requests: write`. The
second job is a copy of `detection-accuracy-comment` from spec 077 with the names changed.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13); GitHub Actions YAML and bash.
**Primary Dependencies**: stdlib `argparse`/`pathlib`; `actions/upload-artifact@v7` and
`actions/download-artifact@v8` (both already used); `gh api`. No new dependencies.
**Storage**: CI-only files under `$RUNNER_TEMP`.
**Testing**: `@pytest.mark.unit` tests in `tests/unit/test_benchmark_regression.py`.
**Constraints**: `benchmarks/` is outside `mypy ziran/` but under `ruff`; annotate anyway.

## Constitution Check

- Hexagonal architecture: no change under `ziran/`.
- Type safety: annotated functions; no new data structure.
- Tests: unit tests carry `@pytest.mark.unit`; test first.
- Simplicity: one flag, one helper; no new dependency; library logging untouched (G5-LIB-LOGGING).

## Code trace (develop @ 3e7eb6b)

- `regression_check.main()` collects metrics (this loads `AttackLibrary`, which logs
  `attack_library_initialized` to stdout), prints `_format_markdown(...)` or `_format_summary(...)`
  and exits 1 on a regression.
- `benchmark.yml` ran the gate (text), then the base metrics, then `$(... --format markdown)`
  into `gh pr comment`; that step had no `if: always()`, so a failed gate skipped it.

## Public contract

- `regression_check.COMMENT_MARKER = "<!-- ziran-benchmark-coverage -->"`.
- `--comment PATH`: write `COMMENT_MARKER`, the markdown report and the delta note to PATH
  (parents created), before the exit code is decided.

## Workflow shape

- Top level: `permissions: contents: read`.
- `benchmark` job: checkout, uv, Python, `uv sync`, `generate_all.py`, base checkout and base
  metrics (PR only, continue-on-error), the gate with `--comment` on PRs, upload of
  `benchmark-results` (always) and of `benchmark-coverage-comment` (always, PR only,
  continue-on-error).
- `benchmark-comment` job: `needs: benchmark`, `if: always() && github.event_name ==
  'pull_request'`, concurrency `benchmark-comment-<PR number>`, `permissions: pull-requests:
  write`, download then post or edit, both steps continue-on-error.
