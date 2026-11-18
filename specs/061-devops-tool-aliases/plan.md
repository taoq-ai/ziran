# Implementation Plan: map read_secrets and execute_command to existing chain capabilities

**Branch**: `ziran-devops-alias` | **Date**: 2026-10-29 | **Spec**: [spec.md](spec.md)

## Summary

Add two entries to `_FRAMEWORK_ALIASES` in `ziran/application/knowledge_graph/tool_aliases.py`.
The anchored lookup spec 056 built (squash, optional `tool` prefix, optional `results`/`json`
suffix, whole-id match, `mcp__` ids skipped) already does the rest.

## Technical Context

- **Language**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
- **Dependencies**: none new.
- **Testing**: pytest, `@pytest.mark.unit`; `canonical_tool_name` cases in the existing
  parametrized test, and an in-memory `AttackKnowledgeGraph` with every pair linked both ways
  (the ground-truth runner's graph shape) with `analyze(include_cycles=False)`.
- **Scope**: one source file, one test file, one docs page, this spec.

## Constitution Check

- Hexagonal: data change inside `application/knowledge_graph`; no import changes. PASS
- Type safety: two dict entries; the test helper is annotated. PASS
- Tests: unit tests for both names, the near misses and the chain. PASS
- Extensibility: aliases stay one table, as spec 056 left it. PASS
- Simplicity: two entries; no pattern, analyzer or classifier change. PASS

## Design

```python
    # DevOps agent tools (spec 061)
    "readsecrets": "secrets_manager",
    "executecommand": "execute_code",
```

`secrets_manager` to `execute_code` is an existing pattern (`cloud_secret_to_rce`, critical).
Candidates probed on the four DevOps tool ids with cycles off: `read_secret_file` or
`secrets_manager` as the source, with `shell_execute`, `shell` or `shell_tool` as the target,
give no chain; `read_secret_file` with `execute_code` gives `file_to_rce` through the generic
`read_file` pattern. Only `secrets_manager` with `execute_code` reaches a secret-specific type.

## Files

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/tool_aliases.py` | two alias entries, docstring names them |
| `tests/unit/test_tool_aliases.py` | alias cases and one chain test |
| `docs/concepts/tool-chains.md` | short table after the RAG names |

## Verification outside this repository

- Dev split: ziran-paper `study/scripts/p5.py --side dev` with `--v1-sha` at 8943b83 and at the
  branch head, and `study/scripts/dev_benchmark.py run` at both. Both scripts open dev scenario
  files only.
- Every agent a dev scenario names: chains before and after, cycles off and on.

## Risks

- Any agent with a tool named exactly `execute_command` now takes every `execute_code` pattern,
  and one named `read_secrets` takes both `secrets_manager` patterns. That widens findings on
  real agents, post-hoc for the study.
