Verdict: PASS
Gate: arch
Item: G4-HARD-SET
PR: taoq-ai/ziran#510
Head: 68cd3694fc5416662c4016fa36b94769f2dcc84e
Confidence: medium
Breaking: no (minor: new --categories/--crossfire flags, new optional result and baseline fields, a wider DetectionCategory Literal; #509's flags, keys and exit codes are unchanged)

## Findings
- [medium] blocks: no. Plan item G4-INDICATOR-TIERS acceptance 1 ("crossfire flagged pairs at most 60% of the baseline count") still cannot be met: flagged is now 15,060, of which 13,890 are not indicator hits. The lead should name `crossfire.indicator_flagged` (1,170, so at most 702) or the spec-021 subset (509, so at most 305). This is a plan edit, not a defect in this PR.
- [low] blocks: no. The frozen indicator copies still drift silently when a vector YAML changes. This is recorded under the spec's Assumptions, so it is a two-way choice.
- [low] blocks: no. CATEGORIES now defaults to all eight, which widens semantic_detection.py and two_tier_judging.py. The docs' two-tier section (detection-accuracy.md:312, 359-360) still describes the 222-example committed result, and that result no longer reproduces from the default dataset. This is not under Assumptions; nothing breaks today.
- [low] blocks: no. Nothing runs --crossfire in CI: #509 merged without it, and this PR leaves the workflow alone. Crossfire stays a manual measure.

## Probes
Delta f231770..68cd369: merge commit 86177d5 (parents f231770 and a5cadd3, which is origin/develop with #509 and #505), then fix commit 68cd369 (docs, spec, plan, two tests). Fresh git archive copy of 68cd369 with its own uv sync --frozen; every command ran under timeout 120; only the touched test files ran locally.
Conflict resolution, benchmarks/detection_regression.py, diffed against origin/develop: it keeps #509 whole (MetricSnapshot, result_snapshots, gate_failures, render_comment with example counts, --comment/--base-result, the pipeline and per_detector fields, and the old-baseline F1-only fallback). The 078 additions are added on top: the CrossfireResult import, SliceSnapshot, the crossfire and per_category_confusion fields, from_result filling them, the --crossfire flag passed to run_benchmark, keep-the-recorded-crossfire on update, and a crossfire line in _render under #509's `failures` signature. No #509 line is dropped or altered.
#509 unit-test stubs: `lambda _d, **_kw` is needed because main now calls run_benchmark(dataset, crossfire=...). The stubs still return the same fixed results, so the gate assertions are unchanged; test_base_result_feeds_comment_and_gate_still_fails still fails the gate on (77, 0, 1, 150).
Baseline: a fresh `--update-baseline --crossfire` into a scratch file equals the committed file on every key except the timestamp. That covers pipeline_f1, per_detector_f1, dataset_size 447, pipeline (115/96/19/217, recall 0.8582, FPR 0.3067), per_detector, all 8 per_category_confusion keys, and crossfire (677 vectors, 930 prompts, 291,090 pairs, 15,060 flagged, indicator 1,170 pairs from 171 vectors).
The gate still bites (end-to-end copies, edited dataset, gate run against the committed baseline):
- One lost detection (det_indicator_near_miss_008 made a bland miss) exits 1 with "pipeline recall 0.8507 is below baseline 0.8582". F1 fell only 0.0039, which the F1 rule alone would let through.
- One new false positive (det_borderline_001 benign made to match a success indicator) exits 1 with "pipeline FPR 0.3099 is above baseline 0.3067".
- My first FP probe, on det_indicator_near_miss_001, left the numbers unchanged because that example is already one of the 40 FPs. I retargeted it to borderline, where every benign reply is a TN.
Gate at head: OK, F1 0.6667 equals the baseline. Touched tests: test_detection_regression_gate.py, test_detection_hard_set.py, test_detection_regression.py, test_detection_accuracy_harness.py and test_semantic_detection_harness.py, 41 passed.
closed: from_result per-slice untested at 68cd369 (test_from_result_writes_per_category_confusion added).
Docs merge: coherent. #509's recall/FPR paragraph sits next to the 078 crossfire and per-slice paragraphs. The new note that the base side scores only the categories it knows matches #509's example-count warning in render_comment (detection_regression.py:203). The crossfire table and spec numbers match the 677-vector run.
CI (gh pr checks 510, read once): lint, typecheck, benchmark, CodeQL, dependency-audit, detection-accuracy-gate and detection-accuracy-comment pass. test 3.11/3.12/3.13 and integration-test are pending, so the full suite and coverage are unmeasured at this read. No leftover processes.
Confidence medium: the merge is verified line by line and both gate rules bite end to end, but the CI pytest jobs and coverage were pending.

## Residual risk
The pytest jobs had not finished at this read. The per-slice baseline is reported, not gated, so a trade between slices is caught only if G4-INDICATOR-TIERS checks it as its acceptance requires.
