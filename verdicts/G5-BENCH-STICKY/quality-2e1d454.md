Verdict: PASS
Gate: quality
Item: G5-BENCH-STICKY
PR: taoq-ai/ziran#518
Head: 2e1d454a30d643ccdb48985c70a3396b6e7a278c
Confidence: medium
Supersedes: none

## Findings
- [low] .github/workflows/benchmark.yml:136 blocks: no. Untested: reversing `startswith(` to `contains(` in the jq selector survives; the test's forged comment is by a non-bot user, so a bot comment that quotes the marker mid-body would be edited. Only github-actions[bot] writes there, so no concrete harm; a bot comment with the marker mid-body would make it a test.
- [low] benchmarks/regression_check.py:194 blocks: no. On a regression the note reads "Changes are relative to the PR base; the regression gate uses baseline.json". The regression list itself (678 -> 677 in the probe) is measured against baseline.json, not the PR base. The note's second clause says so; the wording is accurate but easy to misread.
- [low] tests/unit/test_benchmark_regression.py:206 blocks: no. The jq selector test skips when jq is absent (present locally and on ubuntu runners, where CI's test jobs decide it); the final `test (3.11)` check was still pending when read.

## Probes
Ran `tests/unit/test_benchmark_regression.py` in a `git archive 2e1d454` copy: 14 passed, 0 skipped (jq present). The five new tests all reach real code: the first runs `regression_check.py` as a subprocess on real metrics; it fails before the change (unknown `--comment` exits 2).
Mutants on the copy, each under `timeout 120` with only that file run, 13 total, 12 killed:
- comment written only after the exit check: killed by test_regression_still_writes_comment_and_fails
- marker moved off the first line: killed by test_comment_file_starts_with_marker_and_holds_no_log_line
- marker removed: killed by the same test
- a log line injected into the comment: killed by the same test
- `--comment` never written: killed by the same test
- delta note condition swapped: killed by test_comment_note_follows_delta_baseline
- exit code 1 changed to 0: killed by test_delta_uses_passed_metrics_gate_uses_committed_baseline and test_regression_still_writes_comment_and_fails
- jq bot-login filter dropped: killed by test_comment_selector_edits_only_the_bot_marker_comment
- jq marker filter dropped: killed by the same test
- top-level pull-requests: write added: killed by test_only_the_comment_job_can_write_and_it_runs_no_repo_code
- checkout added to the comment job: killed by the same test
- continue-on-error removed from the post step: killed by the same test
- jq `startswith` to `contains`: SURVIVED (re-run in a fresh copy: still survives), see the first finding.
`actionlint .github/workflows/benchmark.yml`: no output. Action versions (upload-artifact@v7, download-artifact@v8) and the concurrency group match detection-accuracy.yml.
Live PR (`gh api repos/taoq-ai/ziran/issues/518/comments`): exactly one comment, id 6978457051, by github-actions[bot], created 12:23:29Z, last edit 12:26:15Z. GraphQL `userContentEdits` shows three bodies: head 9614753 with no regressions; head 61c8ffb with `:x: **Regressions detected:**` and "Total attack vectors decreased: 678 -> 677"; head 2e1d454 with no regressions. That covers acceptance 1, 2 and 4: run 44303612763 (probe head) had the benchmark job fail at "Run benchmark regression check" while benchmark-comment succeeded and posted.
Baseline: `git diff origin/develop HEAD -- benchmarks/results` is empty, so the revert f24328f restored it. The PR's non-spec files are workflow, regression_check.py and the test only.
CI via `gh pr checks 518`: benchmark, benchmark-comment, lint, typecheck, CodeQL, dependency-audit and the other gates pass; test (3.11) was pending at read time.
Confidence is medium because that last required check was pending and a fork or Dependabot token (acceptance 5) was not run live; it holds by construction (needs: benchmark, continue-on-error on every comment step, job result of benchmark unaffected).
Simplicity: none to delete; `_write_comment` reuses `_format_markdown`, and the old `2>/dev/null || echo "Benchmark check failed"` fallback path is already gone.
closed: none (first round)

## Residual risk
The PR code (regression_check.py at head) writes the comment markdown, so a same-repo PR author controls the comment body; this is the same trust shape as detection-accuracy.yml and the write token sits in the no-checkout job. The test job for 3.11 had not finished at read time.
