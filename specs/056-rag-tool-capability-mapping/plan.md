# Implementation Plan: map RAG-agent tool names to existing chain capabilities

**Branch**: `ziran-rag-mapping` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)

## Summary

Add a small framework alias table to `ziran/application/knowledge_graph/tool_aliases.py` and
consult it from `canonical_tool_name` wherever that function returns an id unchanged today. Keys
are squashed (lowercase, non-alphanumerics removed). The squashed id must equal a key after an
optional `tool` prefix, with an optional `results`/`json` suffix. MCP ids are not mapped.

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
#: non-alphanumerics removed); the squashed id must equal a key (anchored).
_FRAMEWORK_ALIASES: dict[str, str] = {
    "recursiveurlloader": "http_request",
    "tavilysearch": "browse_url",
    "vectorstorequery": "vector_store_read",
    "vectorstoresearch": "vector_store_read",
}

_FRAMEWORK_NAME = re.compile(r"(?:tool)?(.+?)(?:results)?(?:json)?")

def _framework_alias(tool_id: str) -> str:
    m = _FRAMEWORK_NAME.fullmatch(_NON_ALNUM.sub("", tool_id.lower()))
    return _FRAMEWORK_ALIASES.get(m[1], tool_id) if m else tool_id
```

`canonical_tool_name` calls `_framework_alias(tool_id)` where an id that is not a Claude Code
built-in is returned unchanged today. The MCP branch still returns a non-outbound id unchanged:
the server name can carry capability words (`mcp__send_email__tavily_search`) that the alias
would drop. Claude Code results are untouched.

The alias replaces the whole id, so the match is anchored: an id with other words around a
name (`shell_execute_tavily_search`) keeps its own words and chains.

## Files

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/tool_aliases.py` | table, helper, one call site, docstring |
| `tests/unit/test_tool_aliases.py` | new parametrized cases and regressions |
| `tests/unit/test_chain_analyzer.py` | new `TestRagToolNames` class |
| `docs/concepts/tool-chains.md` | short section listing the new names |

## Risks

- An id that equals a mapped name takes that one keyword, even if the tool does more. Every
  alias in this module has that limit.
- A graph holding only the three tools still yields no chain (spec, Edge Cases).
