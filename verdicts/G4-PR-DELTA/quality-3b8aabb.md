Verdict: PASS
Gate: quality
Item: G4-PR-DELTA
PR: taoq-ai/ziran#509
Head: 3b8aabbcc16f1c6d3a0591206bc97c61e539a51f
Confidence: medium
Breaking: no

## Findings
- [low] tests/unit/test_detection_regression_gate.py:0 blocks: no. Untested: no test reads the committed benchmarks/results/detection_accuracy_baseline.json for the `pipeline` key; with `pipeline` and `per_detector` stripped from that file all 14 gate tests still pass, so an old-schema baseline would silently turn the recall and FPR rules off (relevant to the #510 merge, see Residual risk). A one-line test asserting `DetectionAccuracyBaseline.model_validate_json(BASELINE_PATH.read_text()).pipeline is not None` covers it.
- [low] benchmarks/detection_regression.py:164 blocks: no. Review thread 4610982497 (github-code-quality bot, implicit string concatenation in a list) is not a defect: lines 163-164 are one intended wrapped literal, and the comment 6973116766 renders it as one line. The thread is still unanswered; reply or wrap the two literals in parentheses so the answered-threads condition holds before merge.
- [low] .github/workflows/detection-accuracy.yml:0 blocks: no. No `concurrency` group on the comment job: two pushes racing could both find no marker comment and post two. Not seen in this PR's three pushes; a note only.
- [low] benchmarks/detection_regression.py:46 blocks: no. Recall and FPR are rounded to 4 places before the zero-tolerance compare, so on a dataset above about 10000 examples a single lost detection could round to equal. Irrelevant at 228 or 447 examples.

## Probes
- Checks at head in a git archive copy (the main checkout's venv with PYTHONPATH on the copy; ziran and benchmarks both resolved to the copy): tests/unit/test_detection_regression_gate.py plus tests/integration/test_detection_regression.py, 14 passed, 0 skipped. `ruff check` and `ruff format --check` on benchmarks and the new test: clean. `mypy benchmarks/detection_regression.py`: no issues. The full `pytest --cov=ziran` was not run locally; CI at this head is green on test 3.11, 3.12 and 3.13, lint, typecheck, integration-test, detection-accuracy-gate, detection-accuracy-comment and CodeQL.
- Mutants on the gate rules, each run in a fresh copy; all killed:
  - recall rule with a 0.02 tolerance, rule removed, or inverted: test_one_lost_detection_fails_on_recall and test_base_result_feeds_comment_and_gate_still_fails fail.
  - recall `<` changed to `<=`: 4 tests fail (the unchanged-result tests among them).
  - FPR rule removed or given a 0.01 tolerance: test_one_added_false_positive_fails_on_fpr fails.
  - FPR `>` changed to `>=`: 4 tests fail.
  - old-file guard `if baseline.pipeline is not None` forced to True: test_old_baseline_without_new_keys_gates_on_f1_only and test_regression_below_tolerance_fails fail.
  - snapshots() old-file fallback removed: test_old_baseline_without_new_keys_gates_on_f1_only fails.
  - F1 tolerance widened: the same two tests fail.
  - fpr arithmetic halved: test_baseline_records_new_fields and test_comment_shows_head_base_and_deltas fail.
  - --base-result fallback (ValidationError dropped from the except): test_unreadable_base_result_falls_back_to_baseline fails.
  - base note blanked: test_base_result_feeds_comment_and_gate_still_fails fails.
- Survivor: stripping `pipeline` and `per_detector` from the committed baseline JSON, 14 of 14 still pass (the first finding).
- Committed baseline JSON equals a fresh `--update-baseline` regen on the head dataset, apart from the timestamp. `--comment` on the head writes the expected table, and the gate exits 0.
- Comment edited, not duplicated: issue comment 6973116766 (github-actions[bot], marker `<!-- ziran-detection-accuracy -->`) was created 08:23:31Z and updated 08:37:48Z, and its footer says head 3b8aabb. It is the only marker comment on the PR, after three pushes (the benchmark.yml reports landed at 08:23, 08:31 and 08:37). The other three bot comments belong to benchmark.yml, which posts one per push and prepends a log line; that is existing behaviour outside this item. The comment lookup selects by user github-actions[bot] and body prefix, so a user-posted fake marker cannot be picked up.
- Workflow reading: the comment job holds pull-requests: write and runs no PR code, only the downloaded artifact. The gate job stays contents: read. `steps.base.outcome` ignores continue-on-error, so a failed base run falls back to the baseline with a warning note. Every step of the comment job is continue-on-error, so the gate's result is unchanged. The base run puts PYTHONPATH on the archived base tree and reads the head dataset.
- Review thread: see the second finding. It is a false positive, not blocking.
- Simplicity: none to delete. The `--format markdown` branch of `_render` predates this PR. MetricSnapshot, render_comment and result_snapshots each have one use and are needed.

## Residual risk
Second merge (#510, G4-HARD-SET, spec 078) edits the same imports, `DetectionAccuracyBaseline` (it adds `crossfire`; this PR adds `pipeline` and `per_detector`), `from_result`, `_render` and `main()`, and rewrites the same baseline JSON (447 examples, pipeline F1 0.6667). It must rebase onto develop and resolve the Python by keeping both field sets, keeping `crossfire=args.crossfire` on `run_benchmark` beside `--comment` and `--base-result`. It must regenerate the JSON with `--update-baseline` on the rebased tree and must not keep its own copy: its current file has no `pipeline` or `per_detector`, and the gate then silently falls back to F1 only, with no test failing (the first finding). Check after the rebase that the regenerated file has `pipeline.recall` and `pipeline.fpr` for the 447-example set.
