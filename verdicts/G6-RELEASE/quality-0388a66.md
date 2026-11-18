Verdict: PASS
Gate: quality
Item: G6-RELEASE
PR: taoq-ai/ziran#530
Head: 0388a666c04f34b0924e1748d85cc2f80dbb7798
Confidence: medium

## Findings
- [low] docs/reference/benchmarks/coverage-comparison.md:199 blocks: no. The Detection Accuracy table in the committed page shows indicator F1 0.64 and pipeline F1 0.67; the committed baseline, `benchmarks/generate_all.py` output and detection-accuracy.md (115/64/19/249 gives F1 0.735) give 0.72 and 0.73. #514 changed the numbers without regenerating the page. Docs only, not gated by CI; regenerate on develop in the next change.
- [low] blocks: no. PR #530 test (3.11/3.12/3.13) and integration-test were still IN_PROGRESS on the pull_request run when read; the push run on develop at the same sha 0388a66 (run 44325688610) passed all of them.

## Probes
- Merge map, `git log --first-parent origin/main..0388a66`: 11 merges (#515 main back-merge, #514, #481, #516, #517, #518, #519, #524, #525, #526, #528). The PR body's "What ships" covers #514 #516 #517 #518 #519 #524 #525 #526 #528 #481; #515 is the back-merge and is correctly not listed. The body's claims match the titles.
- `wuwei evidence taoq-ai/ziran#<n>` for all 11: "no gaps: ready to merge" for each.
- `uv lock --check` in a `git archive` copy at 0388a66: resolved 212 packages, exit 0.
- `benchmarks/regression_check.py` at 0388a66: 677 vectors, 11 categories, 100% OWASP, "No changes from baseline".
- `benchmarks/detection_regression.py`: gate OK, pipeline F1 0.7348 equals baseline, refusal/indicator/side_effect/llm_judge F1 equal baseline, delta 0.
- Doc counts: README "677 vectors in 11 categories, 75/88 ATLAS (14/14 agent-specific), 20 benchmarks" matches `atlas_coverage.py` and `generate_all.py` (677, 75/88, 20, gaps 9/23). Re-running generate_all in the copy changes only the two stale F1 cells above. Body claim "pipeline FPR 0.31 to 0.20, recall unchanged" matches detection-accuracy.md (96/313 to 64/313; TP 115 before and after).
- Removal: no `ziran/interfaces/web`, no `ui` extra in pyproject.toml, `streaming` extra present and in the `all` list, no `ziran[ui]` or `ziran ui` in README, docs, Dockerfile or workflows.
- CI on develop at 0388a66 (push run): CI, Tests, Pentest Eval, CodeQL, Detection Accuracy conclusions success; unit tests ran with `--cov-fail-under=80` and the job passed; integration 245 passed, 2 skipped. The coverage percentage itself is unmeasured by me: the log grep returned no TOTAL line, so I rely on the job passing the 80 gate.
- Local runs used SETUPTOOLS_SCM_PRETEND_VERSION because git archive has no tag metadata; no processes of mine remain.
- Mutants: not run, release merge with no new guard code of its own; each guard change was gated in its own PR.
Simplicity: none, a merge-only release PR adds no code of its own.

## Residual risk
The two stale F1 cells on a published docs page, and the pull_request test run still pending when read. The Docker image `ENTRYPOINT ziran` and the published wheel contents were not built or inspected here.
