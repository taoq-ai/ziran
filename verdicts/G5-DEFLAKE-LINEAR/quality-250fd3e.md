Verdict: PASS
Gate: quality
Item: G5-DEFLAKE-LINEAR
PR: taoq-ai/ziran#516
Head: 250fd3e785fc42006978ce77a9cc6a17f247b3e7
Confidence: medium
Breaking: no

## Findings
- [low] tests/unit/test_provenance_linear.py:108 blocks: no. The self-check's `pytest.raises(AssertionError)` accepts either the ratio assert or the 10 s backstop assert; it does not tell them apart. Mutating the ratio bound from 8 to 80 in a copy still fails the self-check (the quadratic regex stays at 15.9x, so the ratio assert is what fires), so the check works today; a narrower `match` is optional.
- [low] tests/unit/test_hybrid_jobs.py:803 blocks: no. Under the real mutant a failing case now takes about 26 s of CPU (78 s for 3 failures; the old helper took roughly 6 s). Acceptable for a failing run, and it stays within the single-case 10 s backstop logic, but a slow CI runner could run a full regression of this file past a minute or two. No pytest-timeout is configured.
- [low] blocks: no. Process: the PR is test-only (20 lines) and not covered by the CLAUDE.md speckit exemption list (typo, one-line config, comment), but process fit never blocks.

## Probes
- Head in a git archive copy, PYTHONPATH pinned (module path checked to be the copy): `timeout 120 pytest tests/unit/test_provenance_linear.py tests/unit/test_hybrid_jobs.py -k linear` gives 27 passed, 113 deselected, 7.6 s (5.7 s of that is the random-parity test, unchanged).
- Repeat runs: 12 runs of the linear cases (random-parity test deselected), 26 passed each, 1.9 s each, no failure. Builder claimed 20 of 20; I reran 12.
- Builder mutant, fresh archive copy (`_run_spans` reverted to `[m.span() for m in rule.finditer(text)]`): `test_the_mask_scales_linearly` gives 3 failed (`hf_`, `glpat-`, `_eyJ`), 2 passed (`npm_a`, `eyJaaaaaaaa.`), 78 s. Failing ratio 16.4 (0.134 s small, 2.2 s large), so the helper still catches a real quadratic case.
- The two passing cases are not a blind spot: under the reverted code they measure 4.2x (`npm_a`) and 4.2x (`eyJaaaaaaaa.`), the same as head (4.1x, 4.5x). `finditer` is linear on them because every `eyJ` after the first is preceded by an alphanumeric, so the JWT lookbehind rejects it, and `npm_a` is not a run-rule input. The quadratic JWT shape needs a non-alphanumeric run character before `eyJ` (`_eyJ`, `-eyJa.`), which `_eyJ` covers and the parity test covers for `-eyJa.`. Extra probes `eyJ`, `eyJaaaaaaaa`, `eyJaaaaaaaa.aaaaaaa` also give 4.0 to 4.5x under the mutant. Those two cases are decoys that guard against false positives, not holes.
- Helper mutant (bound 8 changed to 80 in both places, fresh copy): `test_the_helper_fails_a_quadratic_pattern` fails ("DID NOT RAISE"), so the self-check has teeth. Self-check runs in 0.08 s; its quadratic ratio measured 15.9x, above the 12x early-fail line.
- Early stop under 8x and leniency: the old helper also passed on the first large run under 8, so the bound is not looser at the first large run. What changed for leniency: the large value is the min of up to five runs (was three), and the small sample is the min of five four-call samples. The min of small raises the ratio (stricter); the extra large runs only help a case that is already near 8 after noise. A real 7.9x superlinear case (about n^1.49) passes, as it did before; the bound is 8 by design and unchanged, and n log n sits near 4.5x. A genuine quadratic (about 16x) reaches 12x on two runs and fails early. A middling 9 to 11x case would run all five large runs and need a min under 8 to pass, which noise (upward in CPU time) does not produce. Not too lenient.
- Acceptance 3 (CI Tests matrix): `gh pr checks 516` read once. lint, typecheck, dependency-audit, detection-accuracy-gate, pentest-eval-gate pass; test (3.11), test (3.12), test (3.13) were still pending at the read. Unmeasured, not clean.
- Local tests ran only the touched files, every command under `timeout 120`; no ziran pytest processes of mine remain (pgrep on the scratch path found none).

Simplicity: none. The four-call small sample and the five-run loop are the minimum that moves the small sample above timer resolution while keeping runtime near 1.3x; the self-check is needed to prove the helper still fails.

## Residual risk
Test (3.11/3.12/3.13) results were pending at the review; the noise fix is verified only statistically (12 local runs plus the builder's 20). If CI still shows a ratio near 8 on the 2 to 5 ms cases, raise the small call count rather than the bound.
