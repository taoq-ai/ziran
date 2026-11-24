# Tasks: lethal trifecta check for audit, scan and traces

Base: `origin/develop` @ bc179ee. Branch `feat/088-lethal-trifecta`. Test first: T001 runs red
before T002.

## Phase 1 - Tests (US1 to US4)

- [x] T001 `tests/unit/test_trifecta.py`: leg table, bad overrides, the researcher and support
      agents in audit, the baseline (accepted, and not accepted by a pair chain), the flat scan
      with its SARIF, the override by id and by name, one finding per graph agent, hostile tool
      lists at 100 and 101 tools and 20,000-character names, and the CLI reading
      `.ziran/detectors.yaml`.

## Phase 2 - Implementation (FR-001 to FR-006)

- [x] T002 `trifecta.py`: `tool_legs`, `_scopes`, `find_trifectas`.
- [x] T003 `chain_analyzer.py`, `graph.py`: the step, the de-duplication key, `trifecta_roles`.
- [x] T004 `claude_code_audit.py`, `claude_code_baseline.py`: `LT001`, the baseline key.
- [x] T005 `sarif.py`: the `LT001` rule in the scan SARIF.
- [x] T006 `thresholds.py`, `main.py`: the override field and the CLI hand-off.
- [x] T007 Keep the finding at three tool ids (sizing in the spec).

## Phase 3 - Old contract

- [x] T008 Update the tests that pinned the old output: `test_claude_code_audit.py`,
      `test_cli_main.py`, `test_http_adapter.py`, `test_hybrid_settings.py`,
      `test_role_typing_probe_parity.py`, `tests/integration/test_chain_study_v1_equality.py`,
      `tests/integration/test_analyze_traces_alerting.py`.

## Phase 4 - Docs

- [x] T009 `docs/reference/cli.md`, `docs/guides/claude-code.md`, `README.md`,
      `examples/24-claude-code-agent-audit/README.md`.

## Phase 5 - Fix round 1 (gate findings)

- [x] T010 `sarif.py`, `ci.py`: a trifecta the gate suppresses carries a SARIF `suppressions`
      entry (`GateResult.suppressed_chains`).
- [x] T011 `infrastructure/config/detectors.py`: an unreadable or non-UTF-8 file is a
      `DetectorConfigError`.
- [x] T012 `benchmarks/ground_truth/run.py`: `url_allowlist` and `no_network_access` mitigate
      `lethal_trifecta`.
- [x] T013 CLI tests: `ziran scan` hands `trifecta_roles` to the graph; `--write-baseline` and
      `--baseline` use it; audit survives a UTF-16 or directory config.
- [x] T014 `trifecta.py`: overrides go through `tool_legs` (a string override raises); the
      agent's tool set is intersected once. Tests for each leg, the secret words, the
      `USES_TOOL` filter and the SARIF level and agent property; no wall-clock assert.

## Slice 2 (A-TRIFECTA-TRACES), base `develop` @ 7006a23

- [x] T015 Tests: the trace order rule (`tests/unit/test_analyzer_service.py`), the delegated
      variant with direction, cycles and hostile delegation graphs, and the ground-truth agents
      (`tests/unit/test_trifecta.py`); run red.
- [x] T016 `trifecta.py`: `egress_after_untrusted`, `_delegated`, bounded evidence.
- [x] T017 `analyzer_service.py`: the order rule and `rule_id` `LT001`.
- [x] T018 Ground truth: two agents and two scenarios; `run.py` and `validate.py` at base and head.
- [x] T019 Old contract: `tests/integration/test_analyze_traces_alerting.py` (one dedup, not two).
- [x] T020 Docs: `docs/reference/cli.md`, `docs/guides/claude-code.md` (regenerated trace output).
