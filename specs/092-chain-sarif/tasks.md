# Tasks: every dangerous chain in the scan SARIF

Base: `origin/develop` @ eee3253. Branch `feat/092-chain-sarif`. Test first: T001 runs red
before T002.

## Phase 1 - Tests (US1 to US3)

- [x] T001 `tests/unit/test_chain_sarif.py`: delegated rule, pair chain levels, shared rule
      risk, fingerprints, hostile names, suppression in both directions, 100 flat tools.

## Phase 2 - Implementation (FR-001 to FR-006)

- [x] T002 `trifecta.py`: `DELEGATED_RULE_ID = "LT002"`.
- [x] T003 `sarif.py`: `_chain_result`, `_chain_rule`, `_trifecta_rule(rule_id, name)`,
      `CHAIN_RULE_ID`, one loop over every chain.

## Phase 3 - Old contract and docs

- [x] T004 Run `test_cicd.py`, `test_cicd_suppressions.py`, `test_trifecta.py`: unchanged, all
      pass.
- [x] T005 `docs/guides/cicd-integration.md`, `docs/reference/cli.md`: the chain rules in SARIF.
- [x] T006 Measure 100 flat tools (sizing table in the spec).

## Phase 4 - Fix round 1 (quality gate)

- [x] T007 Tests: an unknown risk (`info`, `""`, `severe`) gives `warning`; a low chain after a
      critical one leaves `CC001` at 9.0; the `LT002` rule description.
- [x] T008 One `CHAIN_RULE_ID` in `chain_analyzer.py`, imported by `sarif.py`,
      `claude_code_audit.py` and `claude_code_baseline.py`; the fingerprint keeps tool order.
- [x] T009 Spec 088 points forward to this spec for the delegated chain in SARIF.
