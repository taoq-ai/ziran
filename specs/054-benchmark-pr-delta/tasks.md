# Tasks: benchmark PR comment delta from the PR base branch

Base: `origin/develop` @ 7e1ef38. Work on branch `054-benchmark-pr-delta`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys in tests. New tests carry
`@pytest.mark.unit` (they live in the existing marked class). The flag name, formatter signatures,
step ids and paths are exactly those in [plan.md §Public contract](plan.md#public-contract).
Existing tests MUST NOT be modified. Never fabricate output: every number quoted in the PR body
comes from a command actually run.

## Phase 1 - `--delta-baseline` flag (FR-001, FR-002, FR-003; US1.1, US1.2, US2.1, US3.2)

- [ ] T001 Failing tests in `tests/unit/test_benchmark_regression.py`, appended to
      `TestBenchmarkRegression`. Shared local helper (module-level function in the test file) that
      returns a full metrics dict (`total_vectors`, `categories`, `owasp_coverage_pct`,
      `owasp_covered`, `multi_turn_vectors`, `harm_category_count`, `tactics_count`) with
      overrides, so the gate keys not under test are equal everywhere. Each test monkeypatches
      `benchmarks.regression_check._collect_current_metrics`, `BASELINE_PATH`
      (-> `tmp_path / "baseline.json"`) and `sys.argv`, then calls `main()`:
      - `test_delta_uses_passed_metrics_gate_uses_committed_baseline`: current `670/230`,
        committed `445/99`, delta file `661/229`, `--format markdown --delta-baseline <file>`;
        `main()` returns; stdout contains `**Changes:** **Vectors**: +9 | **Multi-turn**: +1` and
        not `+225`. Then rewrite committed baseline with `total_vectors=700` and the delta file with
        `600`; `pytest.raises(SystemExit)` code `1`; stdout contains `:x: **Regressions detected:**`
        and `Total attack vectors decreased: 700 -> 670`.
      - `test_delta_defaults_to_committed_baseline`: same current/committed, no flag; stdout
        contains `**Vectors**: +225 | **Multi-turn**: +131`.
      - `test_unreadable_delta_baseline_is_usage_error` (also takes `capsys`): `--delta-baseline` pointing at a missing
        file -> `SystemExit` code `2` and stderr (`capsys`) contains `cannot read --delta-baseline`;
        same for a file containing `not json`.
      Run `uv run pytest tests/unit/test_benchmark_regression.py` and confirm the first and third
      tests fail (today argparse rejects the unknown flag with code 2 and a different message, which
      is why the message is asserted) while the six existing tests pass.
      `test_delta_defaults_to_committed_baseline` passes before and after: it is the guard that the
      default behaviour does not change.
- [ ] T002 Implement plan §1 in `benchmarks/regression_check.py`: `delta_base` keyword on
      `_format_summary` and `_format_markdown` (delta lines use `delta_base` when given, regression
      check keeps `baseline`), `--delta-baseline` argument with `parser.error` on
      `OSError`/`json.JSONDecodeError`, pass-through in `main()`, one docstring `Usage:` line.
      `_check_regressions` and the exit-1 block unchanged. T001 passes; existing tests pass.

## Phase 2 - Workflow (FR-004, FR-005; US1.3, US2.2, US3.1)

- [ ] T003 Edit `.github/workflows/benchmark.yml` per plan §2: add steps `base_checkout`
      (actions/checkout@v7, `ref: ${{ github.event.pull_request.base.sha }}`, `path: _bench_base`,
      `persist-credentials: false`, `continue-on-error: true`, PR-only) and `base_metrics`
      (`PYTHONPATH: ${{ github.workspace }}/_bench_base`,
      `uv run python _bench_base/benchmarks/regression_check.py --update-baseline`,
      `continue-on-error: true`, runs only if the checkout succeeded); replace the comment step's
      script with the `BASE_OK` branch, `--delta-baseline` pass-through and the success / `:warning:`
      footer line. No other step, trigger or permission changes.
- [ ] T004 Run `uvx --from actionlint-py actionlint .github/workflows/benchmark.yml`; must exit 0.
      Record whether `shellcheck` was available (it is not on the spec author's machine).
- [ ] T005 Local dry run of the base-collection command against an extracted base tree
      (`git archive origin/develop` into the scratchpad, then the step's command with
      `PYTHONPATH` set, or `sys.path.insert` if the sandbox blocks `PYTHONPATH`); then run the head
      markdown step with `--delta-baseline <tree>/benchmarks/results/baseline.json` and record the
      real output (expected: no `**Changes:**` line, since this branch changes no vectors).

## Phase 3 - Baseline refresh (FR-006; US4.1)

- [ ] T006 `uv run python benchmarks/regression_check.py --update-baseline`; commit the regenerated
      `benchmarks/results/baseline.json` as produced (no hand edits). Record the printed line and the
      new `total_vectors` / `multi_turn_vectors` values for the PR body.

## Phase 4 - Gates and live proof (FR-007, SC-002..SC-005)

- [ ] T007 Run and record real output: `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%). `git diff --stat origin/develop`
      shows only the four files in plan §Project Structure plus the spec dir and the expected
      CLAUDE.md agent-context churn; `uv.lock` unchanged.
- [ ] T008 Open the PR against `develop`. Wait for the `Benchmark Coverage` run and the
      "Benchmark Coverage Report" comment; quote its actual `Changes:` line (or state that none was
      printed) and its footer line verbatim in the PR body. If the run or comment cannot be
      observed, mark US1.3 / US3.1 as unverified in the PR body. State that the fallback branch is
      proven by YAML review only unless a base failure occurred.

## Dependencies
T001 -> T002 -> T003 (the workflow passes the new flag) -> T004 -> T005. T006 after T002 (any
order relative to T003-T005). T007 after all code tasks; T008 last.
