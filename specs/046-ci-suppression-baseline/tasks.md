# Tasks: CI finding suppression baseline and regression gate (accept / suppress / regress)

Base: `origin/develop` @ 7d4132e. No prerequisite feature. Siblings #447, #399, #217 run in
parallel; only `ziran/interfaces/cli/main.py` is shared (#399 edits `scan` / `_display_results`;
keep this feature's edits inside `ci` and `_display_gate_result`).

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New tests carry
`@pytest.mark.unit` and live in `tests/unit/test_cicd_suppressions.py`. Names, fields, rule names,
YAML keys, output names and printed formats are exactly those in
[plan.md §Public contract](plan.md#public-contract). Existing tests MUST NOT be modified: they are
the "absent file = unchanged" regression net.

Local helpers in the new test file (copied pattern of `tests/unit/test_cicd.py`, not imported):
`_campaign(*, attacks=(), chains=(), critical_paths=(), phase_vulns=(), success=False)` building a
`CampaignResult(target_agent="test_agent", ...)` (one `PhaseResult(phase=..., success=...,
trust_score=0.8, duration_seconds=0.0, vulnerabilities_found=list(phase_vulns))` when
`phase_vulns`), `_attack(vector_id="v1", category="prompt_injection", severity="critical", **kw)`,
`_chain(tools=("read_file", "http_request"), risk_level="critical",
vulnerability_type="data_exfiltration")`, and `_entry(finding: GateFinding, **kw) ->
SuppressionEntry` (fingerprint/content hash taken from `QualityGate._findings(...)`, `reason=
"accepted risk"`, `added_by="sec-team"`). `TODAY = date(2026, 1, 2)`.

## Phase 0 — Golden outputs (SC-003)

- [ ] T001 Before any code change, on a detached `origin/develop` checkout of this worktree, write
      two fixture results to the scratchpad (not committed): `clean.json` (no findings,
      `success=false`) and `risky.json` (one successful critical attack, one successful medium
      attack, one critical chain, a critical path, `success=true`). In an empty scratch cwd, with
      `COLUMNS=120`, `GITHUB_OUTPUT=<dir>/out.txt`, `GITHUB_STEP_SUMMARY=<dir>/summary.md`, run
      `uv run --project <worktree> ziran ci <fixture> --sarif <dir>/r.sarif > <dir>/stdout.txt`
      for each fixture and record the exit code in `<dir>/exit.txt`. Keep the directory for T020.

## Phase 1 — Domain identity and file models (FR-001..FR-004, FR-006 fields)

- [ ] T002 [P] Failing tests `TestFingerprints`:
      - `attack_fingerprint("test_agent", "v1", "prompt_injection") ==
        "a8fe72c13edad12d1df1d032a83ebe7a5b0320e125cfc28de5321a0421117f6e"` (today's web value);
        `findings_extractor._compute_fingerprint is attack_fingerprint`.
      - `chain_fingerprint` differs per `target_agent` and per `vulnerability_type`; two
        `_findings` chains with the same type and different tools share one fingerprint.
      - `attack_content_hash` changes with severity and with category; `chain_content_hash`
        changes with tool order, tool set and `risk_level`; all four return 64 lowercase hex.
- [ ] T003 [P] Failing tests `TestSuppressionModels`: valid entry with and without `expires`
      (`date` and ISO string); rejected (`ValidationError`): unknown key in entry and in file,
      `version: 2`, missing `version`, missing/empty/whitespace `reason` or `added_by`, 63-char or
      uppercase-hex `fingerprint` / `content_hash`, `expires: "soon"`; `SuppressionFile(version=1)`
      has `entries == []`; `entry.expired(d)` false on `expires == d`, true on `expires < d`, false
      when `expires is None`; models are frozen. `GateResult(status=PASSED)` defaults: `findings ==
      []`, three counts 0, `suppressions_applied is False`, `suppressed_attacks() == {}`.
- [ ] T004 Implement plan §1 in `ziran/domain/entities/ci.py` and plan §2 in
      `ziran/interfaces/web/services/findings_extractor.py`. T002-T003 pass;
      `tests/unit/test_findings_extractor.py` passes unmodified.

## Phase 2 — Gate classification, counts, violations, policy rule (FR-005..FR-008)

- [ ] T005 [P] Failing tests `TestLoadSuppressions` (`tmp_path`): valid YAML (with an unquoted
      `expires: 2026-12-31`) loads; a list document raises `ValueError` containing `expected
      mapping`; schema errors raise `ValueError` (pydantic); missing path raises
      `FileNotFoundError`.
- [ ] T006 [P] Failing tests `TestGateSuppressions` (default `QualityGateConfig()`, `today=TODAY`
      unless stated):
      - US1.1 `test_suppressed_attack_does_not_fail`: only `A` + matching entry -> `passed`,
        `finding_counts.critical == 0`, counts `(new, suppressed, regressed) == (0, 1, 0)`,
        `suppressions_applied`, summary contains `Suppressions: new 0, suppressed 1, regressed 0`,
        `suppressed_attacks() == {0: "accepted risk"}`.
      - US1.2 `test_suppressed_chain_does_not_fail`.
      - US1.3 `test_all_suppressed_default_config_passes`: `A` + `C`, `critical_paths=[["cap_x",
        "v1"], ["read_file", "composition::data_exfiltration::read_file->http_request"]]`,
        `phase_vulns=["v1"]`, `success=True`, entries for both -> `passed`, `exit_code == 0`.
      - `test_unbacked_data_source_path_fails`: as US1.3 plus path `["cap_x", "sensitive_data"]`
        -> `policy_violation` whose message contains `1 unbacked critical path(s)`.
      - `test_unbacked_phase_vulnerability_fails`: as US1.3 plus `phase_vulns=["v1", "v9"]` ->
        `policy_violation` (message contains `1 unbacked phase vulnerability(ies)`).
      - `test_policy_disabled_ignores_paths`: `fail_on_policy_violation=False` + data-source path
        -> no `policy_violation`.
      - `test_composition_node_id_matches_graph`: `_composition_node_id(_chain())` equals
        `AttackKnowledgeGraph().add_chain_finding(DangerousChain(**_chain(), exploit_description=
        "x"))`.
      - US1.4 `test_entry_valid_on_expiry_day`: `expires=TODAY` still suppresses.
      - US2.1 `test_chain_tools_change_regresses`: entry for `C`, result with tools `["read_file",
        "send_email"]` -> state `regressed`, `regressed_findings == 1`, `finding_counts.critical ==
        1`, violation `suppression_regressed` whose message contains the entry fingerprint,
        `failed`.
      - US2.2 / US2.3: severity change on `A`, `risk_level` change on `C` -> `regressed`.
      - US2.4 `test_evidence_and_text_changes_stay_suppressed`: entry for `A`; result `A` with
        different `evidence` (incl. `tool_calls`), `agent_response`, `prompt_used`, `vector_name`
        -> `suppressed`.
      - US2.5 `test_category_change_is_new`.
      - Edge `test_duplicate_fingerprints`: two `data_exfiltration` chains with different tools,
        entries for both content hashes -> both suppressed; entry for only one -> other regressed.
      - US3.1 `test_expired_entry_does_not_suppress`: `expires=date(2026, 1, 1)` -> `A` is `new`,
        critical threshold violation, `suppression_expired` message contains the fingerprint and
        `2026-01-01`.
      - US3.2 `test_expired_unmatched_entry_fails`.
      - Edge `test_expired_and_active_entries`: an active entry with another hash plus an expired
        entry with the matching hash -> `regressed` + `suppression_expired`.
      - Edge `test_stale_entry_ignored`: unexpired entry matching nothing -> no violation.
      - US4.1 `test_new_finding_fails`: entry for `A`, result `A` + `B` (`vector_id="v2"`) ->
        `(1, 1, 0)`, `finding_counts.critical == 1`, `max_critical_findings` and
        `severity_threshold_critical` violations.
      - Edge `test_unsuccessful_attacks_not_classified`; `test_info_severity_counted_in_states_only`.
      - Violation order: thresholds, `policy_violation`, regressed (finding order), expired (file
        order).
- [ ] T007 [P] Failing tests `TestAbsent`: for each fixture of `tests/unit/test_cicd.py` shape
      (clean, risky, composition-only, `success=True` with no findings), `evaluate(r)` and
      `evaluate(r, None)` give today's `status`, `violations` (incl. the verbatim
      `"Critical attack paths or tool-composition chains were found"`), `finding_counts` and
      `summary` (no `Suppressions:`), `suppressions_applied is False`, every finding `new`.
- [ ] T008 Implement plan §3 in `ziran/application/cicd/gate.py`. T005-T007 pass;
      `tests/unit/test_cicd.py` passes unmodified (incl. `QualityGate._count_findings(camp)`).

## Phase 3 — SARIF and GitHub Actions (FR-010, FR-011)

- [ ] T009 [P] Failing tests `TestSarifSuppressions`: `A` suppressed + `B` new -> the `A` result
      has `suppressions == [{"kind": "external", "justification": "accepted risk"}]`, the `B` result
      has no `suppressions` key, rules unchanged; `generate_sarif(r)` and `generate_sarif(r, gate)`
      with no file are equal and contain no `suppressions` key; `write_sarif(r, p, gate)` writes it.
- [ ] T010 [P] Failing tests `TestGitHubActionsSuppressions`: `emit_annotations(r, gate)` returns
      one annotation (for `B`); `emit_annotations(r)` unchanged (two). `write_step_summary(gate,
      r)` omits `A`'s vector name from "Vulnerabilities Found", contains the `### Suppressions`
      table with `| New | 1 |`, `| Suppressed | 1 |`, `| Regressed | 0 |`, and `| Critical | 1 |`;
      with no file the summary equals today's (no `### Suppressions`).
- [ ] T011 Implement plan §4 (`sarif.py`) and §5 (`github_actions.py`). T009-T010 pass.

## Phase 4 — CLI (FR-009, FR-012, FR-013)

- [ ] T012 [P] Failing tests `TestCiCommandSuppressions` (`CliRunner`, `monkeypatch.chdir(tmp_path)`,
      `GITHUB_OUTPUT` / `GITHUB_STEP_SUMMARY` pointed into `tmp_path` via `monkeypatch.setenv`):
      - US7.1 auto-load: `.ziran/suppressions.yaml` suppressing the only critical finding -> exit 0,
        stdout contains `Suppressed: 1`.
      - US7.2 `--suppressions other.yaml` wins over a cwd file that would fail.
      - US7.3 `--suppressions missing.yaml` -> exit 2.
      - US7.4 malformed auto-loaded file (and malformed `--suppressions` file) -> exit 1, stdout
        contains `Error loading suppressions`.
      - US4.2 `test_ci_prints_fingerprints`: file with `version: 1` only, one new finding -> stdout
        contains `fingerprint=<fp>` and `content_hash=<hash>` (full 64 hex, unbroken) and exit 1.
      - US6.3 `$GITHUB_OUTPUT` contains `new_findings=`, `suppressed_findings=`,
        `regressed_findings=` lines after the four existing ones.
      - US6.1 via CLI: `--sarif` output has `suppressions` on the suppressed result.
      - US5.1 absent: no `.ziran/`, run -> stdout has no `fingerprint=` / `Suppressed:`,
        `$GITHUB_OUTPUT` has exactly the 4 existing lines, SARIF has no `suppressions` key.
- [ ] T013 Implement plan §6 in `ziran/interfaces/cli/main.py` (`ci` + `_display_gate_result`
      only). T012 passes; `tests/unit/test_cli_main.py` passes unmodified.

## Phase 5 — Proof, docs, gates

- [ ] T020 Re-run the T001 commands with the implemented code in fresh empty scratch cwds and
      `diff -r` against the T001 directories: the diff MUST be empty (SC-003). Record the exact
      command and its (empty) output for the PR body.
- [ ] T021 [P] Docs per plan §9: `docs/guides/cicd-integration.md` `## Suppressing Accepted
      Findings`; `docs/reference/cli.md` `--suppressions` row. Any console sample pasted is copied
      from a real `ziran ci` run on a scratch fixture.
- [ ] T022 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%; includes `tests/unit/application/test_scanner_size.py`).
      `git diff origin/develop -- uv.lock` empty. Commit per plan "Release note"; push; PR to
      `develop` linking #395 with the T020 result.

## Dependencies
T001 before any code change. T002-T003 -> T004 -> T005-T007 -> T008 -> T009-T010 -> T011 -> T012
-> T013 -> T020 -> T021 -> T022. `[P]` tasks within a phase can be written together.
