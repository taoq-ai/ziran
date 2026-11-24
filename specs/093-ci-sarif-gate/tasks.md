# Tasks: `ziran ci` gates a ziran SARIF file

Base: `origin/develop` @ 2988b9a. Branch `feat/093-ci-sarif-gate`. Test first: T001 runs red
before T002.

## Phase 1 - Tests (US1, US2)

- [x] T001 `tests/unit/test_ci_sarif_gate.py`: run properties, gate parity, CLI parity, foreign
      and malformed SARIF.

## Phase 2 - Implementation (FR-001 to FR-005)

- [x] T002 `sarif.py`: run properties, `properties.severity` and `graph_path`,
      `campaign_from_sarif`.
- [x] T003 `main.py` `ci`: load a SARIF through `campaign_from_sarif`.

## Phase 3 - Old contract, Action and docs (FR-006)

- [x] T004 Update the chain-property equality tests; run `test_chain_sarif.py`,
      `test_cicd.py`, `test_cicd_suppressions.py`, `test_blast_radius_report.py`,
      `test_trifecta.py`, `test_cli_main.py`.
- [x] T005 `action.yml` `result-file` text; `action-test.yml` gates a SARIF.
- [x] T006 `docs/guides/cicd-integration.md`, `docs/reference/cli.md`.
