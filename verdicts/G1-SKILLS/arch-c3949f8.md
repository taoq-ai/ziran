Verdict: PASS
Gate: arch
Item: G1-SKILLS
PR: taoq-ai/ziran#470
Head: c3949f874d536e87a3a01115c295a24c33ca3301
Confidence: high
Breaking: no

## Findings
- [low] plugins/ziran/.claude-plugin/plugin.json:3 blocks: no. Versioning contract: the plugin `version` (0.1.0) is bumped by hand only. Claude Code refreshes an installed plugin only when it changes, and nothing (release-please `extra-files` or a test) ties a skill edit to a bump. This is recorded under Assumptions in the spec and PR body as a follow-up. Until that lands, a skill fix merged without a bump never reaches installed users.
- [low] plugins/ziran/skills/audit-agents/SKILL.md:20 blocks: no. Version skew between the served skills and the released CLI: the GitHub default branch is `develop`, so `/plugin marketplace add taoq-ai/ziran` serves the skills from develop. The drift test checks them against the develop CLI, but the skills tell users to install `ziran>=0.42.0` from PyPI. This holds today (`git diff v0.42.0 c3949f8 -- ziran/interfaces action.yml` is empty, as the spec's assumption says). However, nothing guards the floor when a later skill names a flag added after the last release. Candidate: pin the floor to the version the drift test runs against, or mention it in the release checklist.
- [low] plugins/ziran/skills/threat-model-agent/references/atlas-chains.md:1 blocks: no. Single source of truth: the chain-type to ATLAS mapping now lives only in markdown. This is in scope by the promise, and no code mapping exists (`grep -rn "vulnerability_type\s*=" ziran` shows only chain_analyzer.py). When the follow-up item puts ATLAS IDs into the CLI output, the table and `test_atlas_table_covers_every_chain_type` should be pointed at that code mapping. Otherwise two mappings will drift.
- [low] tests/unit/test_claude_plugin_skills.py:254 blocks: no. Two test-layer notes. (1) The unit-marked module shells out to the external `claude` CLI when one is on PATH; CI skips it because `claude` is absent there. (2) The unit-marked dry run probes localhost:8899. Constitution III keeps real external adapters in integration tests, so `test_claude_plugin_validate_strict` fits better under `@pytest.mark.integration`.
- [low] tests/unit/test_claude_plugin_skills.py:205 blocks: no. Source coupling: single-tool chain types are scraped from `chain_analyzer.py` with a regex on `vulnerability_type="..."`. This holds for every producer today: all four `DangerousChain(` sites are in chain_analyzer.py, and three take `pattern_info["type"]` from the YAML. A future type built from a constant or a variable would be missed silently.

## Probes
- Promise and acceptance read with `wuwei plan show G1-SKILLS` (tier full). Diff: `git diff --stat origin/develop...c3949f8` gives 15 files, +1161, and `--name-only | grep ^ziran/` is empty. FR-008 and constitution I (hexagonal) hold, and the root SKILL.md is unchanged.
- The tree copy was made with `git archive c3949f8` into scratch. `pytest tests/unit/test_claude_plugin_skills.py`: 21 passed, including both `claude plugin validate --strict` cases, since the claude CLI is installed locally. `ruff check` and `ruff format --check` on the test file are clean.
- Contract probe M1 (fresh copy): renamed the CLI option `--max-cost` to `--max-spend`. The drift test fails with `set-up-scan/SKILL.md: --max-cost: not an option of any command it names`.
- Contract probe M2 (fresh copy): renamed one `type:` in chain_patterns.yaml to `brand_new_type`. `test_atlas_table_covers_every_chain_type` fails with `['brand_new_type']`.
- Contract probe M3 (fresh copy): renamed the action.yml input `baseline` to `baseline-file`. The action snippet test fails with `undeclared action inputs: ['baseline']`.
- Chain-type producers: `grep -rn "vulnerability_type\s*=" ziran` shows that chain_analyzer.py (YAML types plus the literal `unrestricted_execution`) and claude_code_baseline.py (pass-through) are the only producers, so the test's union covers every type ZIRAN reports.
- Release skew: `git diff --stat v0.42.0 c3949f8 -- ziran/ action.yml` shows only chain_patterns.yaml (+database_exfiltration, +repl_exfiltration) and tool_aliases.py. The CLI and action are unchanged since 0.42.0, so the `ziran>=0.42.0` floor holds at this head. `gh repo view --json defaultBranchRef` returns develop.
- `taoq-ai/ziran@v0` in the snippet: `git ls-remote origin refs/tags/v0` shows that it exists. The prose inputs severity-threshold, sarif-output and ziran-version, and the outputs status, exit-code and sarif-file, are all declared in action.yml.
- CI at this head (`gh pr view 470 --json statusCheckRollup`, read once): all 16 checks are SUCCESS, including test 3.11/3.12/3.13, typecheck, lint and integration-test.
- Breaking: the change is additive only. No existing CLI, API, config, action input or file format changes. The new outward names (marketplace `ziran`, plugin `ziran`, install id `ziran@ziran`) are fixed by the approved promise.
- Confidence is high: no runtime code changes, and each of the three contract couplings the promise depends on was shown to fail on drift in a fresh copy. What would lower it: the GitHub-shorthand install from the default branch after merge, which is unmeasured here (the builder reports a branch-ref install succeeded).

## Residual risk
Skill freshness for installed users depends on manual plugin version bumps, and the PyPI floor depends on manual upkeep. Neither is guarded by a test yet. Both are recorded or noted follow-ups, not regressions.
