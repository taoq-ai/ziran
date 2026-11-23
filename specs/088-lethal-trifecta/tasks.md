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
