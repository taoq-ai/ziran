# Implementation Plan: lethal trifecta check for audit, scan and traces

**Branch**: `feat/088-lethal-trifecta` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ bc179ee

## Summary

A new module gives each tool its trifecta legs and finds, per agent scope, the agents whose
tools cover all three. `ToolChainAnalyzer.analyze` calls it as its last step, so every caller
of `analyze` gets it. The audit splits it out as `LT001`, the scan SARIF adds the same rule, the
baseline keys chains by tools and type, and `.ziran/detectors.yaml` gains `trifecta_roles`.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: Pydantic v2 (the new `DetectorThresholds` field), stdlib only
otherwise. No new dependencies.
**Storage**: none. The override rides `AttackKnowledgeGraph.trifecta_roles` in memory, beside
`graph.warnings`.
**Testing**: `tests/unit/test_trifecta.py` (new) plus the touched tests of the old contract.

## Constitution Check

- Hexagonal architecture: `trifecta.py` sits in the application layer's knowledge graph and
  imports only application and domain code. The interfaces layer (CLI) reads the file through
  the existing infrastructure loader and hands the mapping inward.
- Type safety: annotated, mypy strict clean; the override is a `Literal` list in Pydantic.
- Simplicity: one module of name rules and one scope walk; no option or flag. The check is on
  for every `analyze` call; an operator corrects a tool through the override.

## Design

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/trifecta.py` (new) | `tool_legs`, `_scopes`, `find_trifectas`, `RULE_ID = "LT001"` |
| `ziran/application/knowledge_graph/chain_analyzer.py` | trifecta step after the typed step; de-duplication key carries the agent |
| `ziran/application/knowledge_graph/graph.py` | `trifecta_roles` attribute |
| `ziran/application/static_analysis/claude_code_audit.py` | `LT001` rows; `trifecta_roles` through `agent_chains` and `audit_claude_code` |
| `ziran/application/static_analysis/claude_code_baseline.py` | `LT001` dropped like `CC001`; chains keyed by tools and type; `trifecta_roles` through both entry points |
| `ziran/application/cicd/sarif.py` | `LT001` rule and results from `dangerous_tool_chains` |
| `ziran/application/detectors/thresholds.py` | `trifecta_roles` field |
| `ziran/interfaces/cli/main.py` | `_trifecta_roles()` reads the file (warn on invalid); audit and scan pass it |
| `docs/reference/cli.md`, `docs/guides/claude-code.md`, `README.md`, `examples/24-claude-code-agent-audit/README.md` | the rule, the legs, the override, regenerated outputs |

The trifecta step runs after the typed step: the typed step skips pairs the table already
reports, and a two-tool trifecta must not hide a typed pair.

## Verification

- Red: `tests/unit/test_trifecta.py` on a `git archive` copy of base fails at collection (no
  `trifecta` module).
- Green: the new file and the touched tests of the old contract, under `timeout -s KILL 120`.
- `benchmarks/generate_all.py` on base and head: only timing fields of
  `performance_metrics.json` differ; `regression_check.py` reports no change from baseline.
