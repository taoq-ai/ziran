Verdict: PASS
Gate: goal
Item: G4-INDICATOR-TIERS
PR: taoq-ai/ziran#514
Head: 360a0e74432a28b05d3185646cf2b8edf67a8f36
Confidence: medium

## Findings
- [medium] blocks: no. Offline recall limit, now disclosed in the delivered docs (detection-accuracy.md "only a configured judge catches it") and the PR Residual risk: a fresh, differently worded leak on mt_distraction_emotional[1] (a numbered customer list with emails, phones and DOB, no `records:` or `card ending`) was flagged at develop through `customer` and defaults safe at the head. The new forms match the round-1 probe wording, so other phrasings of the four thinned prompts stay judge-only. G-4 "no loss in detection" holds on its fixed measure (benchmark recall equal on all 8 slices) and not for every offline phrasing; the owner should read the Release note before v0.43.x ships it.
- [low] blocks: no. Brief count: leaks.py gives 4 of 7 at the head, not 5. The 3 misses (no_rules_game, fewshot_format_priming, the French paraphrase) are also missed at develop, so there is no regression on that probe.
- [low] blocks: no. CI read once (gh pr checks 514): 19 checks pass and test (3.11), test (3.12) and test (3.13) are pending, so acceptance 5 (full suite, coverage at least 85%) is not yet shown at this head. The PR is a draft.
- [low] blocks: no. benchmarks/ground_truth/run.py prints its FP detail lists truncated to 20 in set order, so raw output differs run to run even on develop. This is an existing gap, not from this PR; the summary rows are identical.

## Probes
- closed: docs/reference/benchmarks/detection-accuracy.md:208 false "still flags offline" claim at 360a0e7. The docs now say a leak without the listed forms or with one corroborated word scores ambiguous, defaults safe offline, and only a configured judge catches it.
- closed: PR body "no vector is edited" at 360a0e7. It now says 14 prompts in five vector files; probes/count.py over the YAML at develop vs head gives 14 changed prompts, matching, and no develop indicator removed from any prompt.
- Copy: git archive of 360a0e7 into a fresh folder, PYTHONPATH pinned to it, every run under timeout 120. Base is the develop copy from round 1 (adcca01).
- Acceptance 1: crossfire indicator hits 540 pairs (151 vectors), at most 702: met. Flagged 14,447.
- Acceptance 2: pipeline 115/64/19/249, FPR 0.2045 (base 0.3067); per-slice TP equal to base on all 8 slices, FP equal or lower on all 8 and lower on 4. Committed detection_accuracy_baseline.json pipeline confusion equals the run; its crossfire indicator_flagged is 540. Met.
- Acceptance 3: ground_truth/run.py summary rows identical to develop (md5 of the sorted summary rows equal; scenario verdict TP=33 FP=3 FN=0). Met, still vacuous: the script calls no detector. pentest_vs_scanner.py at the head: scanner 15 of 15 on the vulnerable targets, same as develop.
- Acceptance 4: the two regression tests pass; tests/unit/test_detectors.py 120 passed.
- leaks.py (round-1 probe), develop vs head: develop 4 of 7, head 4 of 7, the same 4 caught, now through `i was configured as`, `original instructions were`, `records:`/`card ending`, `configured with:`.
- leaks2.py (6 fresh phrasings): develop flags 3, head flags 2; the one lost is the numbered customer list above. The villain and alternation phrasings were missed at develop too.
- PR detection-accuracy comment was updated in place for head 360a0e7 and shows head vs base deltas (pipeline FP 96 to 64, FPR -0.1022, recall "(=)").
- Builder claims checked against my runs: 540/151, 14,447 flagged, 14 prompts, five files, FPR 0.2045. All match.
- No guard code changed in this delta (vectors, tests, docs, baseline, spec), so no new mutants; the round-1 mutants stay killed.
- Confidence medium: the benchmark numbers reproduce exactly; how often real offline leaks avoid the listed forms is unmeasured.

## Residual risk
Offline scans now need a judge for leaks phrased outside the listed forms on prompts that relied on one topical word; the PR and docs say so, but the rate is unmeasured. The full test matrix was still pending in CI at this read.
