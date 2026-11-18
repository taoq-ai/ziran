Verdict: PASS
Gate: quality
Item: G1-SKILLS
PR: taoq-ai/ziran#470
Head: c3949f874d536e87a3a01115c295a24c33ca3301
Confidence: medium

## Findings
- [low] tests/unit/test_claude_plugin_skills.py:301 blocks: no. test_scan_dry_run_offline: the dry run against target-local.yaml (http://localhost:8899) does attempt loopback HTTP discovery (about 1 s of probes, "0 discovered") and still prints "Configuration valid"; the test asserts only exit 0, so it passes with or without a listener on 8899. It is not strictly "no network" and does not prove reachability. set-up-scan step 4 says "Fix any error before step 5" without telling the user that "Capabilities 0 discovered" on a remote target means the endpoint was not reached (step 3's `ziran validate` is the reachability check). Note for the review notes.
- [low] tests/unit/test_claude_plugin_skills.py:292 blocks: no. `"suppressed 1" in gated.output` asserts on CLI prose rather than a record; the first-run `exit_code != 2` assertions in the audit round trip and the triage commands only show the arguments parse. Acceptable for the stated acceptance (exit code is not 2), and the SARIF file existence and baseline exit 0 back them.
- [low] tests/unit/test_claude_plugin_skills.py:311 blocks: no. The `claude plugin validate --strict` tests skip when the claude CLI is absent (CI has none), so manifest validity is guarded in CI only by the builder's local run; the acceptance allows this with a recorded reason.

## Probes
- Confidence is medium because prose claims in the skills that no test executes (rule meanings, fingerprint behaviour) are not guarded, and the GitHub-shorthand install is unmeasured.
- Copy of head via `git archive c3949f8` in scratch with SETUPTOOLS_SCM_PRETEND_VERSION: `pytest tests/unit/test_claude_plugin_skills.py` gives 21 passed, 0 skipped (claude CLI present locally, so both validate --strict params ran).
- `ruff check` and `ruff format --check` on the new test: clean. `mypy` on the test: clean. No file under ziran/ is in the diff (git diff --stat origin/develop...head).
- CI at head read once with `gh pr checks 470`: test 3.11, 3.12, 3.13, integration-test, lint, typecheck, dependency-audit, frontend-build, CodeQL, detection-accuracy-gate and pentest-eval-gate all pass.
- Mutants, each in the scratch copy and restored after (diff -rq against the worktree showed no residue):
  - rename CLI `--write-baseline` to `--write-baselines` in ziran/interfaces/cli/main.py: killed by test_skill_cli_references_exist[audit-agents] and test_audit_sarif_baseline_round_trip.
  - rename the `transaction_hijack` chain type in the ATLAS table: killed by test_atlas_table_covers_every_chain_type.
  - replace AML.T0048.000 with the nonexistent AML.T0999: killed by test_every_atlas_id_in_plugin_is_known.
  - rename the Action snippet `baseline:` key: killed by test_audit_skill_action_snippet_uses_declared_inputs.
  - frontmatter `name: setup-scan` for dir set-up-scan: killed by test_skill_frontmatter[set-up-scan].
  - rename the suppression template key `added_by` to `added_bys`: killed by test_triage_commands_parse_and_accept_skill_suppressions (the CLI rejects unknown keys).
  - `--llm-rpm` to `--llm-rps` in set-up-scan: killed by test_skill_cli_references_exist[set-up-scan], and the failure names the file.
  - `--coverage minimal` in set-up-scan: killed by the same test through the Click.Choice check.
  - The checker's own guards (unknown command, unknown option, Choice value, extra positional such as `--phases a b`, bare flag, command groups) are pinned by test_checker_names_file_and_stale_reference, test_checker_checks_flags_named_alone and test_checker_walks_command_groups.
- Spot-checked skill claims against code: BL001 to BL004 meanings match claude_code_baseline.py; `--phases` is a repeatable Choice matching the skill's repeat-the-flag advice; `ziran scan` does not read ziran.yaml.
- Parser probes (the repo's own process names none for this item): the checker is exercised by 3 synthetic-input tests and 14 live skill/markdown inputs, all passing.
- Mutants surviving: none.
- Simplicity: none to delete. The checker reuses Click's own parser (`make_parser`) instead of a hand-written flag table, and the ATLAS test reuses the AtlasTechnique enum and chain_patterns.yaml. The regex on chain_analyzer.py for single-tool types is a source scan, but it is pinned by the `unrestricted_execution` assertion.
- Wall-clock and shared-state check: the only date use is an offset from today for `expires`; all outputs go to tmp_path; env vars are cleared by monkeypatch.

## Residual risk
Skill prose beyond commands and flags (rule meanings, fingerprint behaviour) is checked only where the tests execute it; a future CLI behaviour change in those prose claims will not trip the drift test. The GitHub-shorthand install path stays unmeasured until the branch is public.
