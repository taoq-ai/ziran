Verdict: PASS
Gate: quality
Item: standalone-pr501
PR: taoq-ai/ziran#501
Head: 3086d4a1d498bc16abfaeb3542563396959da9ba
Confidence: medium

## Findings
- [low] tests/unit/test_poc_generator.py:183 blocks: no. The new test covers a multi-line prompt and the default two-line imports block, but not a custom `PoCConfig` whose template strings contain braces; I probed that by hand and it is fine (str.format does not re-parse substituted values).
- [low] blocks: no. CI jobs test (3.11/3.12/3.13), integration-test and the plugin-audit job were still pending when I read the checks once; every completed check was green. Merge should wait for them.

## Probes
- Fetched; reviewed head 3086d4a1 via git archive copy in the scratchpad (not the main worktree).
- Head: tests/unit/test_poc_generator.py 20 passed; with test_cli_main.py and test_cli_smoke.py 158 passed. ruff check, ruff format --check and mypy on the poc module are clean.
- Mutant (revert the generator to develop, keep the new test): test_python_poc_compiles_with_multiline_values FAILS with `IndentationError: unexpected indent` at line 2; the other 19 pass. So the test fails without the fix and reaches the real consumer (compile of generated source).
- Template fields: all placeholders (tpl.shebang, result.vector_name/vector_id/severity, result.category.value, campaign_id, owasp_str, generated, generator_label, imports_block, prompt_escaped, indicators_repr, tpl.vulnerable_text_match/vulnerable_tool_match/not_reproduced) are supplied to .format; none missing. Attribute access on tpl and result works under str.format (same as the old f-string). The `{{...}}` escapes render as single braces in the output, and the generated `{matched}` text (from tpl.vulnerable_text_match) stays intact. A new `{...}` placeholder in the template would raise KeyError at generation, so the escapes are guarded by the test.
- Generated-file probe: 12 combinations (prompts with braces, `{{y}}`, `%s`, triple quotes, backslashes, tab and indented lines, empty, and the literal text `{result.severity} {tpl.shebang}`; vector name with braces; campaign id `c{1}`; indicators containing quotes and braces). Every file compiled, exec'd, `ATTACK_PROMPT` equalled the input exactly, and `reproduce()` run against a stub adapter returned True with the expected `[!] VULNERABLE — Matched indicators: [...]` line. Values with braces are not re-substituted.
- Unaffected paths: the diff touches only the `generate_python_poc` hunk. `generate_curl_poc` and the Markdown generator are unchanged lines (curl still uses `textwrap.dedent(f"""`; its prompt is one JSON line, so no multi-line defeat).
- Standards: Conventional commit and gitflow target (develop) per CLAUDE.md; no new dependency; speckit skipped with a recorded assumption, which the repo exempts for a trivial one-function fix (process fit, never blocks); PR body has Test, Assumptions and Rollback.
- Not changed, existing: a vector_name containing `"""` or a run instruction containing `"` still produces unsafe output (outside this diff; `_escape_python_string` covers only the prompt).
- Simplicity: none. The `.format(...)` call with named values is the minimal fix (f-string plus dedent cannot be made correct); the explanatory comment is justified; the `generated` and `generator_label` kwargs are required because format cannot call methods.

## Residual risk
Low. Behaviour matches the old template for every case that previously compiled; remaining risk is a future template edit adding an unescaped brace, which now fails loudly in the test.
