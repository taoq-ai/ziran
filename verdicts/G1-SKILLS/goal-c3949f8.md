Verdict: PASS
Gate: goal
Item: G1-SKILLS
PR: taoq-ai/ziran#470
Head: c3949f874d536e87a3a01115c295a24c33ca3301
Confidence: high

## Findings
- [low] blocks: no. Goal G-1's measure says "a CI test that runs every skill's commands against examples/". The approved promise narrows this to "the offline commands", and the test runs exactly the ones the acceptance lists: audit sarif/baseline, report, ci, export-policy, poc and scan --dry-run. Two commands the skills give are offline but are only flag-checked, never run: `ziran init --non-interactive` (set-up-scan) and threat-model-agent's step-5 recipe (`ziran audit` on a scratch agent file). I ran both by hand at the head and both work (init exit 0; the scratch agent gave 2 CC001 rows, and 0 after removing WebFetch). Follow-up: run them in the drift test.
- [low] blocks: no. Goal G-1 says the skills "tag findings with MITRE ATLAS IDs". The delivered work maps chain types to ATLAS in a markdown table, and the CLI output still carries no ATLAS ID. The promise put the CLI change out of scope on purpose, and the skills say so in plain words ("Findings carry no ATLAS ID; use the table"). This is scoped, not drift.
- [low] blocks: no. The plugin `version` 0.1.0 is not tied to the package release. A skill edit reaches installed users only after a manual bump, and no test enforces the bump. The PR records this as an assumption, with release-please extra-files as the follow-up.
- [low] blocks: no. Whether each skill triggers on a real prompt is unmeasured; no headless model run was made (the PR says so under Review notes).

## Probes
- `wuwei plan show G1-SKILLS`: read the promise and the 10 acceptance scenarios. Compared the builder's explain-back in the PR body with them: it matches the promise (four skills, root marketplace, drift test, no ziran/ change).
- Diff `git diff --stat origin/develop...c3949f8`: 15 files, all inside the promise's file list. `git diff --stat ... -- ziran/ SKILL.md pyproject.toml uv.lock` is empty.
- In a git archive of the head (scratch): `uv run pytest tests/unit/test_claude_plugin_skills.py` gave 21 passed. The claude CLI was present, so the two strict-validate tests ran too.
- Acceptance 1: `claude plugin validate --strict` on the archive root and on plugins/ziran: both exit 0.
- Acceptance 2: isolated CLAUDE_CONFIG_DIR, then `marketplace add <archive>`, then `install ziran@ziran`, then `details`: "Skills (4) audit-agents, set-up-scan, threat-model-agent, triage-findings". `find ~/.claude/plugins ~/.claude/settings.json -newer marker` is empty. The installed cache contains references/atlas-chains.md, so the skills' `../threat-model-agent/...` links resolve.
- Acceptance 4 mutant: renamed `--max-campaign-tokens` in ziran/interfaces/cli/main.py:299 in the copy. The drift test fails with "set-up-scan/SKILL.md: --max-campaign-tokens: not an option of any command it names". Restored afterwards.
- Acceptance 9 counts, read with python over chain_patterns.yaml: 80 distinct types (126 patterns), plus 1 analyzer literal (`unrestricted_execution`, the only `vulnerability_type="..."` literal under ziran/). The table has 18 rows. This matches the PR body ("18 rows covering all 81").
- Acceptance 10: CI at the head (run 39117647805) is all green on 3.11, 3.12 and 3.13, plus lint, typecheck and integration. Unit coverage on 3.12 is 85.58%, which meets the item's 85%. Note that CI itself enforces only 80. Unit 3210 passed and 2 skipped, integration 193: total 3405, matching the PR body.
- Claims in the skill text, checked against the live CLI and source: the audit JSON row keys and exit codes 0/1/2; the CC000/CC001/SA001/3/4/7 and BL001-4 rules, with BL rows forced to critical (claude_code_baseline.py:_violation); action.yml inputs, defaults and outputs, and that tag `v0` exists; ci exit 2 on a missing suppressions file; fingerprints printed only when a suppressions file is loaded (0 without, shown with one); `.ziran/suppressions.yaml` is the default; SuppressionEntry is extra=forbid with reason and added_by required; suppression_regressed and suppression_expired exist in gate.py; scan frameworks, coverage, phases and caps match `scan --help`; the skill's target YAML loads through load_target_config; the capability table matches tool_aliases.py (including UNRESTRICTED_EXEC_TOOLS, read_secret_file, git_push and the outbound verbs).
- Plugin markdown: no `ziran <cmd>` or `--flag` sits outside code (where the checker could not see it), and every relative link resolves.
- Root SKILL.md "ZIRAN IS NOT": the skills stay on agent security testing. No alignment checks or guardrail features are added; export-policy is an existing command.
- Confidence is high: I reproduced every acceptance scenario myself, either at the head or from the head's CI run. Only skill triggering in a live model session remains unmeasured.

## Residual risk
Skill wording can drift in ways the checker cannot see, such as prose claims about output fields and exit semantics. The drift test checks only commands, flags, choice values, action inputs and ATLAS coverage.
