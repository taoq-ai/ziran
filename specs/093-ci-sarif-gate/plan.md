# Implementation Plan: `ziran ci` gates a ziran SARIF file

**Branch**: `feat/093-ci-sarif-gate` | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13); stdlib `json`, Pydantic v2. No new dependencies.
Touched: `ziran/application/cicd/sarif.py`, `ziran/interfaces/cli/main.py` (`ci`), `action.yml`
(input text), `.github/workflows/action-test.yml`, docs.

## Design

- `generate_sarif` passes the run properties to `_sarif_document`; `_build_result` and
  `_chain_result` add `properties.severity` (and `graph_path` for a chain).
- `campaign_from_sarif(doc) -> CampaignResult` in `sarif.py` validates the envelope, reads the
  run properties and rebuilds `attack_results`, `dangerous_tool_chains`, `critical_paths`,
  `phases_executed` (one `PhaseResult` per phase with findings) and `metadata`. The gate is
  unchanged: `ziran ci` passes the rebuilt result to the same `QualityGate.evaluate`, so the two
  paths share every rule.
- `ziran ci` loads the JSON once; a dict with `runs` goes to `campaign_from_sarif`, the rest to
  `CampaignResult.model_validate`. Errors print `Error loading result:` and exit 1, as now.
- Action: `command: ci` already forwards `result-file`; only the input text changes. The
  self-test gates the fixture JSON with `sarif-output`, then gates that SARIF and compares the
  outputs.

## Constitution Check

Hexagonal layers kept (application builds a domain entity; the CLI calls it); strict mypy; tests
first; no new dependency.

## Test plan

`tests/unit/test_ci_sarif_gate.py`: run properties written; parity of `GateResult` between a
campaign and its SARIF over gate configs and suppressions (the fixture JSON included); CLI exit
codes and outputs match; a foreign SARIF and an audit SARIF name the missing properties;
malformed shapes exit 1. Old contract: the two chain-property equality tests in
`test_chain_sarif.py` and `test_blast_radius_report.py` gain `severity`.
