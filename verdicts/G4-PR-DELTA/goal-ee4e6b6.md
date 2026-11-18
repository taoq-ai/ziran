Verdict: PASS
Gate: goal
Item: G4-PR-DELTA
PR: taoq-ai/ziran#509
Head: ee4e6b6995476d80d0873484db705cce08964043
Confidence: medium

## Findings
- [low] .github/workflows/detection-accuracy.yml:94 blocks: no. Carried from 3b8aabb and not addressed. The base run goes through detection_accuracy.py main(), which loads .ziran/detectors.yaml from the head tree, while the head gate uses built-in thresholds. If a PR adds that file, the head and base columns are scored with different thresholds and the comparison is wrong. No such file is committed today
- [low] blocks: no. The filter lists paths rather than tracing imports, and the PR body now says so. Code the benchmark imports that is still outside the filter: ziran/infrastructure/config/env_yaml.py (the YAML loader for thresholds, which only matters once .ziran/detectors.yaml exists), interfaces/detector.py and interfaces/embedder.py (interfaces only), and logging, telemetry and package __init__ files. None of these changes a detection decision on today's code
- [low] blocks: no. Outside this item: the Benchmark Coverage comment (benchmark.yml) still posts once per push with a structlog line at the top. It needs a follow-up item if that is the comment the owner meant
- [low] blocks: no. The full suite was not run locally (owner rule). At my one read of `gh pr checks 509`, test 3.11, 3.12 and 3.13 were pending; integration-test, lint, typecheck, benchmark and both detection-accuracy jobs passed

## Probes
- closed: relevance filter missed tool_classifier.py, entities/detection.py and config/detectors.py at ee4e6b6. I extracted the pattern lines from the workflow at ee4e6b6 and ran them in bash under timeout 120. These gave true: tool_classifier.py, entities/detection.py, config/detectors.py, interfaces/adapter.py, llm/base.py, pyproject.toml, uv.lock, detectors/refusal.py, vectors/x.yaml and entities/attack.py. These gave false: README.md, frontend/uv.lock, entities/finding.py and benchmarks/accuracy_metrics.py.
- classify_tool mutant at ee4e6b6 (always "low", fresh git-archive copy, timeout 120): the path is now relevant. The rendered comment shows "side_effect | 0/0/36/22 (base 36/0/0/22) | ... F1 0.0 (base 1.0, -1.0)", pipeline (=), "Examples scored: head 228, base 228." Gate exit 0, since per-detector rows never block, by design.
- Complement check at ee4e6b6: the benchmark loads 47 repo files and 25 sit outside the filter. Every one of those 25 is a package __init__ or transitive infrastructure (pentesting, rate_limiting, logging, telemetry, llm/factory, config/env_yaml, entities defence/pentest/phase); see note 2.
- Live: the marker comment is still the single 6973116766. updated_at moved from 08:37:48Z to 09:31:21Z, the footer reads "PR head `ee4e6b6`, base `d61eed8`", the body has "Base: the PR base code scored on this PR's dataset." and "Examples scored: head 228, base 228." There is 1 marker comment in total. detection-accuracy-gate and detection-accuracy-comment passed at this head.
- closed: duplicate first-comment race at ee4e6b6. The comment job now has a per-PR concurrency group (cancel-in-progress false).
- closed: artifact upload outage failing the gate at ee4e6b6. The upload step now has continue-on-error.
- Touched test file tests/unit/test_detection_regression_gate.py: 12 passed (timeout 120).
- The PR body's assumption was corrected: it now says the filter lists paths and does not trace imports.
- The ee4e6b6 diff is limited to the workflow, detection_regression.py, the docs, the spec and the test file. The develop merge 25fa622 was not reviewed as part of this fix.
- Earlier results at 3b8aabb still stand, since the gate rules did not change: 77/0/1/150 exits 1 naming recall, 78/1/0/149 exits 1 naming FPR, the old baseline loads, and the base step imports the base tree.
- No probe processes are left (pgrep).
- Confidence medium: the fix was probed directly and the live comment was read at this head. The full suite was pending at my read, and the fork-token path was never run.

## Residual risk
The filter is a hand-kept path list, so a future detector dependency has to be added by hand. Per-detector regressions show only in the comment and never block.
