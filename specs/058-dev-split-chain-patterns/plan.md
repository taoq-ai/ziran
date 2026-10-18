# Implementation Plan: append sql_query and python_repl to send_email chain patterns

**Branch**: `ziran-dev-patterns` | **Date**: 2026-10-17 | **Spec**: [spec.md](spec.md)

## Summary

Append two entries to the end of `ziran/application/knowledge_graph/chain_patterns.yaml`.
No code changes: the registry loads entries in file order and the analyzer already matches them.

## Technical Context

- **Language**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
- **Dependencies**: none new.
- **Testing**: pytest, `@pytest.mark.unit`, in-memory `AttackKnowledgeGraph` with every tool
  pair linked both ways (the ground-truth runner's graph shape), `analyze(include_cycles=False)`.
- **Scope**: one YAML file, one test file, one docs page, this spec.

## Constitution Check

- Hexagonal: data change inside `application/knowledge_graph`; no import changes. PASS
- Type safety: no new code in `ziran/`; the test helpers are annotated. PASS
- Tests: unit tests for both patterns and for their position. PASS
- Extensibility: patterns are data (YAML), as the library already works. PASS
- Simplicity: two YAML entries; no alias, analyzer or classifier change. PASS

## Design

```yaml
  # ── Email Exfiltration (spec 058) ─────────────────────────────────
  # Appended last so no pair matched earlier changes type (first match wins).
  - source: sql_query
    target: send_email
    type: database_exfiltration
    risk: critical
    category: data_exfiltration
  - source: python_repl
    target: send_email
    type: repl_exfiltration
    risk: critical
    category: framework_tools
```

(Each entry also carries a `description` and `remediation`.)

## Files

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/chain_patterns.yaml` | two entries appended at the end |
| `tests/unit/test_chain_patterns.py` | new `TestDevSplitPatterns` class |
| `docs/concepts/tool-chains.md` | short table listing both patterns |

## Verification outside this repository

- Pattern order against `b813e4f`: compare the ordered `(source, target, type)` lists at
  `b813e4f` and the branch head. ziran-paper's `pattern_diff.py` is planned there but not yet
  built, so the same rule (new, changed or reordered) is applied by a scratch script.
- Dev recall: ziran-paper `study/scripts/dev_benchmark.py run` at the branch head from a scratch
  export, plus a scratch probe that loads only the dev scenario files.

## Risks

- Any id that contains `sql_query` or `python_repl`, paired with an email tool, gains a chain.
  That widens findings on real agents; it cannot change the type of a chain found before.
