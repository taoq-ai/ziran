Verdict: PASS
Gate: quality
Item: poc-dedent
PR: taoq-ai/ziran#501
Head: 3086d4a1d498bc16abfaeb3542563396959da9ba
Confidence: medium

## Findings
none

## Probes
- Head fetched (pull/501/head = 3086d4a1); reviewed in a git archive copy under the scratchpad (quality-poc-dedent), not the checkout.
- tests/unit/test_poc_generator.py at head: 20 passed (0 skipped). The new test test_python_poc_compiles_with_multiline_values passes.
- Regression proof: base source (3086d4a~1) with the new test file: 1 failed, 19 passed. The failure is IndentationError: unexpected indent at poc.py line 2, so the test failed before the fix and reaches the real generate_python_poc and compile().
- Mutant: reversed the brace escape ({{ATTACK_PROMPT[:80]}} to {ATTACK_PROMPT[:80]}): 5 tests fail, including the new one and test_python_poc_contains_prompt. Mutant: revert to the f-string fill (the base): the new test fails (above).
- Differential: for single-line values (one import, one-line prompt, a vector name and indicators containing braces/quotes) head output is byte-identical to base output (0 differences), so the change alters only the multi-line case. With multi-line imports or a multi-line prompt the head output compiles (py_compile ok); base output raises IndentationError.
- Values containing braces ({cmd}, {p}, {x}, {c}) land verbatim in the output, since format does not re-parse substituted values; the test asserts this for the prompt.
- CI at head: all 20 listed checks pass (lint, typecheck, test 3.11/3.12/3.13, integration-test, CodeQL). I did not re-run the full ruff/mypy/coverage locally; uv could not build offline here, so I relied on the CI lint/typecheck results.
- Assertions are on a decision (compiles, shebang first, def at column 0, value preserved), not on prose; no clock/network/shared-file dependence.
- Notes (non-blocking, existing): tpl.* and result.vector_name are interpolated into print("...") lines and the shebang line without escaping, as before; a newline in vector_name would still break the generated file. Not part of this item's promise. The new test does not cover a multi-line imports list directly, but the default config imports and the multi-line prompt exercise the same dedent path.
- Simplicity: none to delete. The change is the smallest root-cause fix (dedent the literal template, then .format); the helper variables already existed. The two dead expression statements above it (result.evidence.get(...) without use) predate this PR and are out of scope.

## Residual risk
Template braces are now a contract: a future literal { or } added to the template without doubling raises KeyError/ValueError at generate time (the existing tests catch it, as the mutant shows). Locally unmeasured: ruff, mypy and coverage percentage (CI green).
