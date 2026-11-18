Verdict: PASS
Gate: arch
Item: G5-BENCH-STICKY
PR: taoq-ai/ziran#518
Head: 2e1d454a30d643ccdb48985c70a3396b6e7a278c
Confidence: high
Breaking: no

## Findings
- [low] .github/workflows/benchmark.yml:102 blocks: no. The comment job is a line-for-line copy of detection-accuracy-comment (diff after renaming shows only the relevance guard, artifact name, two message strings and one shellcheck comment). Copying is the smaller right choice at two copies under constitution VI ("no premature abstractions"); a workflow_call or composite action would need inputs for marker, artifact and label plus permission plumbing. Extract it when a third sticky comment appears. The choice is not under the spec's Assumptions.
- [low] .github/workflows/benchmark.yml:79 blocks: no. The gate now receives --delta-baseline on PRs, so a base metrics file that exists but cannot be parsed would make parser.error exit 2 before the comment is written. Under spec 054 only the comment depended on it. I found no way to reach this: BASE_OK is true only after the base script wrote json.dumps output and exited 0.
- [low] benchmarks/regression_check.py:258 blocks: no. On PR runs the gate's text log line "Improvements:" is now measured against the PR base, not baseline.json, because the two invocations were merged. This touches the CI log only. The gate's pass/fail is still absolute against baseline.json, so spec 054 FR-002 and Option 2 hold, but FR-003's "stdout unchanged" is true only per argument set.
- [low] .github/workflows/benchmark.yml:104 blocks: no. With cancel-in-progress: false, an older run's comment job that is queued after a newer one can overwrite the newer body. The footer's head SHA shows which push it reflects. detection-accuracy.yml has the same limit.

## Probes
- Plan: read with `wuwei plan show G5-BENCH-STICKY`. Spec 080, plan and tasks read. Spec 054 spec and plan checked for the ordering design. Constitution VI read.
- Consistency: I diffed benchmark-comment against detection-accuracy-comment after renaming with sed. The only differences are the expected ones. Top-level permissions, the env-only github.* values, concurrency, continue-on-error, the jq selector and the PATCH/POST flow are identical in shape.
- Ordering vs spec 054: the base checkout and metrics steps stay continue-on-error and write only under _bench_base (BASELINE_PATH is relative to the script's own tree). collect_inventory, collect_owasp_coverage and collect_benchmark_comparison write files only under their own `__main__` --json, so the benchmark-results upload, which now runs after the base step, is not polluted. The gate still compares with the head baseline.json.
- Backward compatibility: `git grep regression_check` at the head finds three callers: the workflow base step (--update-baseline on the base tree's own script, never passed --comment), the gate step, and the usage docs. --comment is optional with default None, and the --format/--delta-baseline/--update-baseline paths are untouched.
- Path filter: .github/workflows/benchmark.yml was added to both the push and pull_request filters, mirroring detection-accuracy's self-inclusion. Benchmark Coverage was already path-filtered, so this adds no required-check deadlock.
- Library logging: `git diff --stat origin/develop...2e1d454 -- ziran/` is empty. Running `regression_check.py --format markdown` at the head still prints `2026-11-18 13:29:43 [info ] attack_library_initialized ...` on stdout, so the root cause is left to G5-LIB-LOGGING as scoped.
- Tests: `timeout 120 pytest tests/unit/test_benchmark_regression.py` in a git archive copy gave 14 passed in 0.56s.
- Mutants, each in a fresh git archive copy, all killed: (1) dropping the github-actions[bot] login clause from the jq selector fails test_comment_selector_edits_only_the_bot_marker_comment; (2) moving _write_comment after sys.exit(1) fails test_regression_still_writes_comment_and_fails; (3) adding pull-requests: write at the top level fails test_only_the_comment_job_can_write_and_it_runs_no_repo_code.
- Live evidence, read once: PR 518 at head 2e1d454 has exactly one github-actions[bot] comment (6978457051). Its first line is the marker, its footer reads `PR head 2e1d454, base 3e7eb6b`, and the benchmark and benchmark-comment checks are SUCCESS. The PR body cites the regression probe run 44303612763, where the benchmark job failed and the same comment showed the regression list.
- Breaking: no, patch. benchmarks/ scripts are not the published package API, the new flag and constant are additive, and the existing flags keep their meaning.
- Confidence high: the workflow matches the proven spec-077 shape, all three guard mutants die, and the live PR shows the sticky behaviour at this head.

## Residual risk
Two copies of the sticky-comment job can drift apart. Fork and Dependabot behaviour is argued from continue-on-error and was not observed on a real fork run.
