# Implementation Plan: `ziran scan` finds tool chains on flat agents

**Branch**: `fix/086-flat-agent-chains` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ 3b0589a

## Summary

Move the co-resident edge loop of `agent_chains` into `AttackKnowledgeGraph`, call it from
`import_adapter_structure` when the structure import linked no two tools, and keep those edges
out of every graph walker but the direct pair rule through one view,
`AttackKnowledgeGraph.structure_view()`. Above the tool cap the skip is a warning in the result.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: NetworkX (`subgraph_view`), stdlib `itertools`. No new dependencies.
**Storage**: none. The `co_resident` edge attribute rides the existing graph export; the
warning rides `CampaignResult.metadata`.
**Testing**: pytest unit tests in the touched test files. A walker that reads a co-resident
edge fails through a raising patch; each scale test has one coarse wall-clock bound.

## Constitution Check

- Hexagonal architecture: the helper and the view live in the application layer's knowledge
  graph; the scanner and the audit both import them from there. The warning key and the
  `CampaignResult.warnings` property live in the domain entity, beside `unmeasured_vectors`.
- Type safety: annotated; no new models.
- Simplicity: one graph method replaces the loop, one view replaces three per-walker bounds,
  one predicate in `structure_import.py`; no option or flag.

## Code trace (develop @ 3b0589a)

- `claude_code_audit.py:50` `agent_chains`: `itertools.permutations(agent.effective_tools, 2)`
  into `add_tool_chain`, then `analyze(include_cycles=False)`.
- `scanner.py:537` `_discover_and_map_capabilities`: adds capabilities, then
  `import_adapter_structure(self.adapter, self.graph)`.
- `structure_import.py`: imports agents, delegation edges, `USES_TOOL` edges and
  `tool -> state:<channel> -> tool` edges.
- `result_builder.py:93`: `ToolChainAnalyzer(self._graph).analyze()` (cycles on).
- `chain_analyzer.py`: the direct rule reads edges through `has_edge`; indirect search, cycle
  search and centrality walk the whole graph.

## Why the design changed (rounds 1 and 2)

Each round bounded the walker a gate caught: cycle search (round 1), then the tool count and
centrality (round 2). At 6bb22a3 indirect search still walked the co-resident edges: two
50-tool agents sharing one tool ran `nx.all_simple_paths(cutoff=3)` through two cliques for
every cross-agent pair and did not finish in 120 s (30+30: 8.75 s, 40+40: 32.9 s, base 0.02 s).
The cause is one: co-resident edges reached every walker. The rule in spec.md fixes the cause,
so a new walker gets the right view by calling `structure_view()`.

## Changes

1. `graph.py`: `add_co_resident_tools`, `has_co_resident_tools`, `structure_view`, and a
   `warnings` list. `find_attack_paths`, `find_all_attack_paths`, `get_cross_agent_attack_paths`,
   `get_critical_nodes` and `_normalized_centrality` read the view.
2. `claude_code_audit.py`: `agent_chains` calls `add_co_resident_tools`.
3. `structure_import.py`: `import_adapter_structure` takes the capabilities (required). It
   returns early when the graph already holds co-resident edges or `_links_tools` (on the view)
   finds a link; else it adds the co-resident sets, per agent when the topology lists agents.
   Over `MAX_CO_RESIDENT_TOOLS` it adds none, logs once and appends one message to
   `graph.warnings`.
4. `scanner.py`: pass `capabilities` to `import_adapter_structure` (same line count).
5. `chain_analyzer.py`: `analyze(include_cycles: bool | None = None)`; `None` means
   `not graph.has_co_resident_tools()`. Indirect search, cycle search and centrality read the
   view. `_candidate_pairs` (the pair table indirect search already built) now feeds the direct
   rule too, so a 100-tool set costs patterns x tools, not patterns x pairs.
6. `result_builder.py`: copy `graph.warnings` to `metadata["warnings"]` when not empty.
7. `phase.py`: `WARNINGS_METADATA_KEY` and `CampaignResult.warnings`.
8. `reports.py`, `html_report.py`, `main.py` (`ziran ci`), `github_actions.py` (step summary):
   print each warning.

## Verification

- Red then green on the touched tests.
- A raising patch on `nx.has_path`, `nx.all_simple_paths`, `nx.descendants`, `nx.simple_cycles`
  and `nx.betweenness_centrality` fails any walker handed a co-resident edge.
- Mutants in a scratch copy: each walker put back on the full graph, the view disabled or
  inverted, each warning output dropped, the repeated-discovery guard removed.
- The gates' probes (team shapes, MCP sizes, pentest `analyze_graph`, handoff teams) at head.
- `ziran audit` on `tests/fixtures/claude_code/*` at base and head, JSON output compared.
- `benchmarks/ground_truth/run.py` at base and head with a pinned `PYTHONHASHSEED`.
- `uv run ruff check`, `uv run ruff format --check`, `uv run mypy ziran/`.
