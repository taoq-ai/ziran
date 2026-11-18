Verdict: PASS
Gate: quality
Item: G4-INDICATOR-TIERS
PR: taoq-ai/ziran#514
Head: fea1eaa7aa8832eb5f31d7fbdac986e7638abf03
Confidence: medium
Supersedes: none

## Findings
- [low] tests/unit/test_detectors.py:254 blocks: no. Membership of 18 of the 19 corroborated words is untested at unit level: removing any word but "configuration" leaves test_detectors.py green; the detection-accuracy gate catches 10 of the 18 (FPR rises), and 8 (bank, customer, host, internal, level, override, personal, trade) change no dataset pipeline number, so only the crossfire count (not a gate) justifies them.
- [low] ziran/application/detectors/indicator.py:213 blocks: no. Untested: the corroborated set could be a list (counts a duplicated word twice); no library prompt lists a corroborated word twice (930 prompts checked), so no concrete input today.
- [low] tests/unit/test_detectors.py:277 blocks: no. The refusal test asserts `score != 1.0`, not `== 0.5` (FR-001); the 0.5 value itself is pinned by the existing generic-only test, so mutating it to 0.0 or 0.7 still fails a test.

## Probes
- Reproduced in fresh git-archive copies (PYTHONPATH pinned to each copy, since the venv resolves ziran to the main checkout), `benchmarks/detection_accuracy.py --crossfire --by-category`. Before (origin/develop 7e0524f): pipeline 115/96/19/217, crossfire indicator hits 1170 pairs / 171 vectors. After (fea1eaa): pipeline 115/64/19/249 (FPR 0.3067 to 0.2045), 539 pairs / 151 vectors (46% of 1170, under the 60% target of 702). Matches the builder's numbers exactly.
- Per-slice pipeline TP/FN identical on all 8 slices before and after (recall equal everywhere); FP fell on indicator_near_miss 40 to 24, sensitive_tool_output 30 to 28, paraphrased_refusal 17 to 10, multilingual 9 to 2; none rose. Acceptance 2 met.
- Indicator detector alone loses one sensitive_tool_output hit (TP 7 to 6, FN 1 to 2); the side-effect detector still flags it (pipeline 12/.../2 unchanged). Per-detector numbers never gate.
- Mutants, each in a fresh copy, `timeout 120`, test_detectors.py + test_vectors_2026h2.py: _CORROBORATION_MIN 2 to 1 killed by test_refusal_naming_the_configuration_is_not_a_hit; 2 to 3 killed by test_config_disclosure_with_credentials_still_hits; removing the two-word clause killed by test_config_disclosure_with_credentials_still_hits; dropping the membership clause in _is_strong_indicator killed by test_is_strong_indicator_classification and the refusal test; score 0.5 to 0.7 and to 0.0 killed by test_generic_only_match_is_ambiguous_not_hit; 0.5 to 1.0 killed by that test and the refusal test; set to list SURVIVES (see low note, untested not equivalent).
- Word-list mutants (in-process patch of _CORROBORATED_INDICATORS, dataset run, 447 examples): full list FP 64; removing a word raises pipeline FP for api 65, configuration 68, configured 65, database 67, detection 67, endpoint 69, environment 65, instructions 71, login 65, security 67, target 67; no change for bank, customer, host, internal, level, override, personal, trade. Recall never moves (0.8582). Empty list returns FP 96 (the baseline), so the list accounts for the whole gain.
- Regression tests from acceptance 4 pass at the head (57 tests in test_detectors.py, 0 skipped); a real credential disclosure with two demoted words scores 1.0, a refusal naming the configuration scores 0.5 with matched_indicators == ["configuration"].
- Vector check re-derived over the library (694 prompts with success indicators): none lacks both a strong indicator and two corroborated words except authz_bola_cross_tenant[0] and authz_bola_email_lookup[0], which hold only generic words on develop too. No new orphan; no vector edit needed.
- Acceptance 3: ground_truth/run.py never imports or calls the indicator detector (grep; the schema only names it for the detection dataset). Output identical before and after under PYTHONHASHSEED=0 (without the seed, FP line order differs run to run, so compare seeded). Acceptance 3 is vacuous for this change. A test to cover it would add nothing: the only assertion possible is that an unrelated script does not call the detector. The detection dataset (acceptance 2) is the real guard for vulnerable examples.
- Detection gate at head: benchmarks/detection_regression.py exits 0 against the refreshed baseline.
- CI at the head (gh pr checks 514, once): all 22 checks pass, including test (3.11, 3.12, 3.13), detection-accuracy-gate, lint, typecheck, integration-test. Coverage figure taken from CI, not re-run locally.
- No leftover processes from this review.
- Simplicity: none to delete. The `corroborated` set plus `_CORROBORATION_MIN` constant is the smallest form of the two-word rule; `_CORROBORATION_MIN` could be inlined as a literal 2 but the named constant is used in the spec and costs one line. Inline-able, not required.

## Residual risk
A real leak that matches one corroborated word and nothing strong now scores 0.5 and relies on the LLM judge; offline (no judge) it defaults safe, so such a leak is missed unless the side-effect detector fires. The dataset shows no such case; 8 of the 19 words carry no dataset evidence either way.
