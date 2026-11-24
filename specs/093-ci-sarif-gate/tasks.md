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

## Phase 4 - Fix round 1 (arch, security, quality gates)

- [x] T007 Tests: unmeasured vectors with failed attacks, one parity case per gate rule, the
      rebuilt chain `graph_path`, a two-run SARIF with a clean first run, an unknown schema,
      the array message, the driver version, `--sarif` skipped on a SARIF input.
- [x] T008 `sarif.py`: `schema` and `attack_count` in the run properties, padding to the count,
      the package version in the driver.
- [x] T009 `main.py`: skip `--sarif` on a SARIF input. `action-test.yml`: outputs through `env:`,
      the default `sarif-output` re-emits nothing.
- [x] T010 Spec and docs: what parity catches, `--policy` on a SARIF.

## Phase 5 - Fix round 2

- [x] T011 Skip `--policy` on a SARIF input; cap `attack_count` at 1,000,000; merge a repeated
      phase; tests for each refused count, the missing key, the cap, the schema default, the
      policy skip and the merged phase.
- [x] T012 Docs: a SARIF input with the default `sarif-output` is gated, not uploaded; an older
      SARIF needs this release.
