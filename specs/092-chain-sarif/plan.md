# Implementation Plan: every dangerous chain in the scan SARIF

**Branch**: `feat/092-chain-sarif` | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13); stdlib `hashlib`/`json`. No new dependencies.
Touched: `ziran/application/cicd/sarif.py`, `ziran/application/knowledge_graph/trifecta.py`
(one constant), docs.

## Design

- `generate_sarif` replaces its `LT001`-only loop with one loop over `dangerous_tool_chains`.
  `_chain_result(chain, rules)` builds the result and registers the rule: `_TRIFECTA_RULES` maps
  the two trifecta types to `LT001` / `LT002`; any other type goes to `CC001`.
- `_trifecta_rule(rule_id, name)` builds both trifecta rules; `_chain_rule()` builds `CC001`,
  raised to the highest risk seen by comparing `security-severity`.
- Suppression reuses `GateResult.suppressed_chains()` by index, as the `LT001` loop did.
- The scan SARIF runs in `ziran ci`, which passes one result object to the gate and to
  `write_sarif`, so the indexes agree.

## Constitution Check

Hexagonal layers unchanged (application layer only); strict mypy; tests first; no new
dependency.

## Test plan

`tests/unit/test_chain_sarif.py`: the delegated rule with agents and tools; each risk level on a
pair chain; the shared rule's highest risk; distinct and stable fingerprints; hostile names
through JSON; suppression of one chain only, unmatched and expired entries, an attack at the
same index; 100 flat tools give one result per chain, under 1,000 bytes each and 2 s.
