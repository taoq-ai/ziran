# Implementation Plan: map RAG-agent tool names to existing chain capabilities

**Branch**: `ziran-rag-mapping` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)

## Summary

Add a small framework alias table to `ziran/application/knowledge_graph/tool_aliases.py` and
consult it from `canonical_tool_name` wherever that function returns an id unchanged today. Keys
are squashed (lowercase, non-alphanumerics removed) and matched as substrings of the squashed id.

## Technical Context

- **Language**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
- **Dependencies**: stdlib `re` (already imported). No new dependency.
- **Testing**: pytest, `@pytest.mark.unit`, in-memory `AttackKnowledgeGraph`.
- **Scope**: one source file, two test files, one docs page.

## Constitution Check

- Hexagonal: the change stays in `application/knowledge_graph`; no new import across layers. PASS
- Type safety: annotated helper, mypy strict. PASS
- Tests: unit tests for the alias map and the analyzer. PASS
- Extensibility: no new attack vector, detector or adapter. N/A
- Simplicity: one dict and one three-line helper; no new module or config. PASS

## Design

```python
#: LangChain-style tool names -> chain-pattern keyword. Keys are squashed (lowercase,
#: non-alphanumerics removed) and match anywhere in the squashed id.
_FRAMEWORK_ALIASES: dict[str, str] = {
    "recursiveurlloader": "http_request",
    "tavilysearch": "browse_url",
    "vectorstorequery": "vector_store_read",
    "vectorstoresearch": "vector_store_read",
}

def _framework_alias(tool_id: str) -> str:
    squashed = _NON_ALNUM.sub("", tool_id.lower())
    return next((kw for key, kw in _FRAMEWORK_ALIASES.items() if key in squashed), tool_id)
```

`canonical_tool_name` calls `_framework_alias(tool_id)` at its two `return tool_id` exits (MCP
non-outbound id; id that is not a Claude Code built-in). Claude Code results are untouched.

Keys are disjoint, so the first-match order does not matter.

## Files

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/tool_aliases.py` | table, helper, two call sites, docstring |
| `tests/unit/test_tool_aliases.py` | new parametrized cases and regressions |
| `tests/unit/test_chain_analyzer.py` | new `TestRagToolNames` class |
| `docs/concepts/tool-chains.md` | short section listing the new names |

## Risks

- Substring matching after squashing can map an unrelated id that contains a key. Keys are
  three-word compounds, which keeps this unlikely.
- A graph holding only the three tools still yields no chain (spec, Edge Cases).
