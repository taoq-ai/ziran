# Implementation Plan: benchmark PR comment delta from the PR base branch

**Branch**: `054-benchmark-pr-delta` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #327 (release 0.42.0) | **Base**: `develop` @ 7e1ef38
**Parallel siblings**: #451 / spec 053, #264 / spec 055. Neither edits `benchmarks/regression_check.py`,
`.github/workflows/benchmark.yml`, `tests/unit/test_benchmark_regression.py` or
`benchmarks/results/baseline.json`. No shared-file coordination needed.

## Summary
Add one optional flag, `--delta-baseline PATH`, to `benchmarks/regression_check.py`: the
`Changes:`/`Improvements:` delta lines use that metrics JSON, while regressions and the exit code
keep using the committed `benchmarks/results/baseline.json`. In `.github/workflows/benchmark.yml`,
for `pull_request` events only, check out the PR base SHA into `_bench_base/`, run that tree's own
`regression_check.py --update-baseline` with `PYTHONPATH` pointing at it, and feed the resulting
JSON to the comment step; if either base step fails, fall back to the committed baseline and say
so in the comment. Refresh `baseline.json` once.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13); GitHub Actions YAML + bash (the benchmark job uses Python 3.12).
**Primary Dependencies**: stdlib `argparse`/`json`/`pathlib` (already imported), `actions/checkout@v7` (already used). No new dependencies.
**Storage**: committed `benchmarks/results/baseline.json` (gate); CI-only `_bench_base/benchmarks/results/baseline.json` (delta, never committed).
**Testing**: pytest `@pytest.mark.unit` in `tests/unit/test_benchmark_regression.py`; drive
`benchmarks.regression_check.main()` with `monkeypatch` (`_collect_current_metrics`,
`BASELINE_PATH`, `sys.argv`), `tmp_path` JSON files and `capsys`. No network, no LLM, no keys.
**Target Platform**: the `Benchmark Coverage` workflow (`pull_request` and `push` on `main`/`develop`,
path-filtered on `ziran/application/attacks/vectors/**`, `ziran/domain/entities/attack.py`,
`benchmarks/**`).
**Project Type**: single Python package + CI workflow.
**Performance Goals**: PR runs gain one shallow checkout and one metrics collection (one
`get_attack_library()` load, about the same cost as the existing comment step).
**Constraints**: `benchmarks/` is outside `mypy ziran/` but under `ruff`; annotate anyway. Line
length 100. `_check_regressions` unchanged.

## Code trace (develop @ 7e1ef38)
- `main()` parses `--update-baseline` and `--format`, calls `_collect_current_metrics()` (which
  calls `collect_inventory()`, `collect_owasp_coverage()`, `collect_benchmark_comparison()`; all
  three call `ziran.application.attacks.library.get_attack_library()`), then `_load_baseline()`
  (reads `BASELINE_PATH = Path(__file__).parent / "results" / "baseline.json"`).
- `--update-baseline` writes `current` to `BASELINE_PATH` and returns.
- `_format_summary(current, baseline)` / `_format_markdown(current, baseline)` both call
  `_check_regressions(current, baseline)`; only when there are none do they compute
  `current[key] - baseline[key]` for the delta line (positive deltas only).
- `main()` then exits 1 if `_check_regressions(current, baseline)` is non-empty.
- Callers: `.github/workflows/benchmark.yml` (gate step: no args; comment step:
  `--format markdown 2>/dev/null || echo "Benchmark check failed"`, then `gh pr comment ... ||
  true`), and `tests/unit/test_benchmark_regression.py` (imports `_check_regressions`,
  `_collect_current_metrics`). Nothing else reads `baseline.json`.

## Local proof of the base-import mechanism (run 2026-10-04, recorded for SC-005)
- The venv's editable install is a path `.pth` (`_editable_impl_ziran.pth` -> project root), so a
  `PYTHONPATH` entry precedes it on `sys.path`.
- An older tree (`git archive d2a77ed^`) extracted to the scratchpad and run with its directory
  prepended to `sys.path` (`runpy.run_path(<tree>/benchmarks/regression_check.py)` with
  `--update-baseline`; the agent sandbox blocks a literal `PYTHONPATH=` prefix, `sys.path.insert(0,
  ...)` is the same lookup order) printed `ziran.__file__` = `<tree>/ziran/__init__.py` and wrote
  `<tree>/benchmarks/results/baseline.json` with `total_vectors 661, multi_turn_vectors 229,
  harm_category_count 11`. The head tree did not change (`git status` clean).
- Same day, head `uv run python benchmarks/regression_check.py --format markdown` printed
  `**Changes:** **Vectors**: +216 | **Multi-turn**: +130` against the frozen baseline (445 / 99):
  the bug reproduced.
- `uvx --from actionlint-py actionlint .github/workflows/benchmark.yml` exits 0 on develop today.
  `shellcheck` is not installed locally, so actionlint's embedded shell check did not run here.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | No `ziran/` code changes. `benchmarks/` is a tooling layer outside the package. |
| II. Type safety | PASS | New/changed functions are annotated; `ziran/` mypy strict unaffected. Metrics stay the existing JSON dict shape (tooling output, not domain data). |
| III. Tests | PASS | Test-first: three unit tests (`@pytest.mark.unit`) for the flag, the gate and the validation. Existing tests unmodified. |
| IV. Async-first | N/A | Synchronous CLI script, as today. |
| V. Extensibility | PASS | No port or vector-format change. |
| VI. Simplicity | PASS | One flag, one optional parameter on two formatters, three workflow steps, no new dependency, no new module. No base-relative gate, no negative-delta rendering. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #327 implementer. Names, flag, paths and step ids MUST NOT change without
updating this file.

### 1. `benchmarks/regression_check.py`

- Module docstring `Usage:` gains one line:
  `uv run python benchmarks/regression_check.py --format markdown --delta-baseline base.json`.
- Formatter signatures (new keyword parameter, default keeps today's behaviour):
  ```python
  def _format_summary(current: dict, baseline: dict | None, delta_base: dict | None = None) -> str
  def _format_markdown(current: dict, baseline: dict | None, delta_base: dict | None = None) -> str
  ```
  Inside each, `ref = delta_base if delta_base is not None else baseline`; the regression check
  stays `_check_regressions(current, baseline)`; only the delta expression changes from
  `baseline.get(key, 0)` to `ref.get(key, 0)`. Structure otherwise unchanged: the delta line is
  still printed only when `baseline` exists and there are no regressions, positive deltas only,
  same keys and labels (markdown: `total_vectors`/Vectors, `multi_turn_vectors`/Multi-turn,
  `harm_category_count`/Harm categories; text: Vectors, OWASP categories, Multi-turn).
- `main()` gains:
  ```python
  parser.add_argument(
      "--delta-baseline",
      type=Path,
      default=None,
      metavar="PATH",
      help=(
          "Metrics JSON (from --update-baseline, e.g. on the PR base) to compute the "
          "Changes delta against; the regression gate still uses results/baseline.json"
      ),
  )
  ```
  After `baseline = _load_baseline()` (implementation note: placed after the `--update-baseline`
  early return, so `--update-baseline` really ignores the flag even when its path is unreadable):
  ```python
  delta_base = None
  if args.delta_baseline is not None:
      try:
          delta_base = json.loads(args.delta_baseline.read_text())
      except (OSError, json.JSONDecodeError) as exc:
          parser.error(f"cannot read --delta-baseline {args.delta_baseline}: {exc}")
  ```
  and passes `delta_base` to the formatter. `--update-baseline` ignores the flag. The exit-1 gate
  block at the end of `main()` is unchanged (uses `baseline`).
- `_check_regressions`, `_collect_current_metrics`, `_load_baseline`, `BASELINE_PATH`,
  `RESULTS_DIR` unchanged. Metrics JSON shape unchanged.

### 2. `.github/workflows/benchmark.yml`

Triggers, permissions, and the steps up to and including "Upload benchmark results" are
unchanged. Insert two steps before the comment step and replace the comment step:

```yaml
      - name: Check out PR base for the coverage delta
        id: base_checkout
        if: github.event_name == 'pull_request'
        continue-on-error: true
        uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: _bench_base
          persist-credentials: false

      - name: Collect PR base benchmark metrics
        id: base_metrics
        if: github.event_name == 'pull_request' && steps.base_checkout.outcome == 'success'
        continue-on-error: true
        env:
          PYTHONPATH: ${{ github.workspace }}/_bench_base
        run: uv run python _bench_base/benchmarks/regression_check.py --update-baseline

      - name: Post benchmark summary as PR comment
        if: github.event_name == 'pull_request'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          BASE_OK: ${{ steps.base_metrics.outcome == 'success' }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          DELTA_ARGS=()
          if [ "$BASE_OK" = "true" ]; then
            DELTA_ARGS=(--delta-baseline _bench_base/benchmarks/results/baseline.json)
            NOTE="_Changes are relative to the PR base \`${BASE_SHA:0:7}\`; the regression gate uses \`benchmarks/results/baseline.json\`._"
          else
            NOTE=":warning: Could not collect PR base metrics (see the \"Collect PR base benchmark metrics\" step); Changes are relative to the committed \`benchmarks/results/baseline.json\`."
          fi
          SUMMARY=$(uv run python benchmarks/regression_check.py --format markdown "${DELTA_ARGS[@]}" 2>/dev/null || echo "Benchmark check failed")
          gh pr comment ${{ github.event.pull_request.number }} --body "$SUMMARY"$'\n\n'"$NOTE" || true
```

- Step ids `base_checkout`, `base_metrics`; directory `_bench_base`; env `BASE_OK`, `BASE_SHA`.
- A skipped `base_metrics` (checkout failed) has `outcome == 'skipped'` -> fallback branch.
- `continue-on-error` keeps a base failure from failing the job; the failing step stays visible
  in the run (orange) and the footer names it.
- `PYTHONPATH` makes the base tree's `ziran` and `benchmarks.*` win over the head's editable
  install; the base script writes only inside `_bench_base/`.
- Implementer may wrap the two long `NOTE=` lines for readability provided the rendered text is
  the same; must keep `actionlint` clean.

### 3. `benchmarks/results/baseline.json`
Regenerated by `uv run python benchmarks/regression_check.py --update-baseline` on the feature
branch (after the code change, which does not alter collected metrics). Committed as produced.

### 4. `tests/unit/test_benchmark_regression.py`
New tests appended to `TestBenchmarkRegression` (existing tests untouched):
- `test_delta_uses_passed_metrics_gate_uses_committed_baseline(tmp_path, monkeypatch, capsys)`
- `test_delta_defaults_to_committed_baseline(tmp_path, monkeypatch, capsys)`
- `test_unreadable_delta_baseline_is_usage_error(tmp_path, monkeypatch, capsys)`

No CLI flag other than `--delta-baseline`; no new module; no output-shape change beyond the
workflow's footer line.

## How each acceptance criterion is proven offline

| Criterion | Proof |
|---|---|
| US1.1 delta from passed metrics | `monkeypatch.setattr(regression_check, "_collect_current_metrics", lambda: current)` with current `670/230`; `BASELINE_PATH` -> `tmp_path/"baseline.json"` holding `445/99`; delta file `661/229`; `sys.argv = ["regression_check.py", "--format", "markdown", "--delta-baseline", str(delta)]`; `main()` returns normally; `capsys` output contains `**Changes:** **Vectors**: +9 \| **Multi-turn**: +1` and not `+225`. Gate keys other than vectors/multi-turn equal across the three dicts. |
| US1.2 default unchanged | Same files, no flag: output contains `**Vectors**: +225 \| **Multi-turn**: +131`. |
| US2.1 gate uses committed baseline | Same test as US1.1, second phase: rewrite `baseline.json` with `total_vectors=700`, delta file `600`; `pytest.raises(SystemExit)` with `code == 1`; output contains `:x: **Regressions detected:**` and `Total attack vectors decreased: 700 -> 670`. |
| US3.2 bad path | `--delta-baseline tmp_path/"missing.json"` -> `SystemExit` code `2` and stderr contains `cannot read --delta-baseline`; same for a file containing `not json`. The message assertion is what makes the test fail today (argparse already exits 2 on the unknown flag). |
| US4.1 refresh | `git diff benchmarks/results/baseline.json` shows the regenerated file; the implementer quotes the command output (`Baseline updated: ...`) and the new `total_vectors` in the PR body. |
| US2.2 push unchanged | Review of the YAML diff: the two new steps and the comment step all carry `if: github.event_name == 'pull_request'` (the collection step via `&&`); no other step changes. `actionlint` clean. |
| US1.3 / US3.1 workflow wiring | Not provable offline. Live: this PR triggers `Benchmark Coverage`; implementer reads the posted comment and quotes the actual `Changes:` line (or its absence) and the footer in the PR body. Fallback branch (US3.1) is proven only by YAML review unless a base failure occurs naturally; reported as such. |
| FR-007 no regressions | Existing six tests pass unmodified; full gate run; `git diff --stat` limited to the four files + spec dir + CLAUDE.md churn; `uv.lock` unchanged. |

## Project Structure

### Documentation (this feature)
```text
specs/054-benchmark-pr-delta/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (files touched)
```text
benchmarks/regression_check.py              # --delta-baseline; delta_base param on 2 formatters
.github/workflows/benchmark.yml             # PR-only base checkout + base metrics + footer
tests/unit/test_benchmark_regression.py     # + 3 unit tests
benchmarks/results/baseline.json            # regenerated once via --update-baseline
```

## Complexity Tracking
None.
