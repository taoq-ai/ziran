# Implementation Plan: `ziran scan` finds tool chains on flat agents

**Branch**: `fix/086-flat-agent-chains` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ 3b0589a

## Summary

Move the co-resident edge loop of `agent_chains` into `AttackKnowledgeGraph`, call it from
`import_adapter_structure` when the structure import linked no two tools, and skip cycle
enumeration in the result builder when the graph holds those edges.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: NetworkX, stdlib `itertools`. No new dependencies.
**Storage**: none. The `co_resident` edge attribute rides the existing graph export.
**Testing**: pytest unit tests in the four touched test files.

## Constitution Check

- Hexagonal architecture: the helper lives in the application layer's knowledge graph; the
  scanner and the audit both import it from there.
- Type safety: annotated; no new models.
- Simplicity: one graph method replaces the loop, one predicate in `structure_import.py`; no
  option or flag.

## Code trace (develop @ 3b0589a)

- `claude_code_audit.py:50` `agent_chains`: `itertools.permutations(agent.effective_tools, 2)`
  into `add_tool_chain`, then `analyze(include_cycles=False)`.
- `scanner.py:537` `_discover_and_map_capabilities`: adds capabilities, then
  `import_adapter_structure(self.adapter, self.graph)`.
- `structure_import.py`: imports agents, delegation edges, `USES_TOOL` edges and
  `tool -> state:<channel> -> tool` edges.
- `result_builder.py:93`: `ToolChainAnalyzer(self._graph).analyze()` (cycles on).
- `chain_analyzer.py`: reads edges only through `has_edge` and the graph shape, never their
  attributes, so the audit's findings do not depend on the edge attributes.

## Changes

1. `graph.py`: `add_co_resident_tools` and `has_co_resident_tools`.
2. `claude_code_audit.py`: `agent_chains` calls `add_co_resident_tools`.
3. `structure_import.py`: `import_adapter_structure` takes the capabilities (required); after the
   import, if `_links_tools` is false, it adds the co-resident edges over the tool ids, per
   agent when the topology lists agents.
4. `scanner.py`: pass `capabilities` to `import_adapter_structure` (same line count).
5. `chain_analyzer.py`: `analyze(include_cycles: bool | None = None)`; `None` means
   `not graph.has_co_resident_tools()`. `result_builder.py` keeps a bare `analyze()`, and the
   pentest `analyze_graph` tool gets the same default.
6. `graph.py` `find_all_attack_paths`: enumerate over `nx.subgraph_view` without co-resident
   edges. Found by `test_enables_links.py::test_end_to_end_mock_scan`, whose six-tool mock scan
   returned 2,678 critical paths instead of 9 before the filter; its counts now leave out chain
   findings and add their two paths each.
7. `structure_import.py` `MAX_CO_RESIDENT_TOOLS`: skip every set when the sets hold more than
   100 tools, with one warning; `chain_analyzer.py`: no betweenness on a co-resident graph over
   `_MAX_CENTRALITY_NODES` (800).

## Verification

- Red then green on the touched tests.
- `ziran audit` on `tests/fixtures/claude_code/*` at base and head, JSON output compared.
- `uv run ruff check`, `uv run ruff format --check`, `uv run mypy ziran/`.
