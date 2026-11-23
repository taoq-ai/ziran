# Feature Specification: `ziran scan` finds tool chains on flat agents

**Feature Branch**: `fix/086-flat-agent-chains`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-FLAT-CHAINS (goal G-a), issue #536 row 1.
**Base**: `develop` @ 3b0589a.

## The promise in our own words

**Design rule.** A co-resident `CAN_CHAIN_TO` edge (`co_resident=True`) says "these two tools sit
in one model's context, so one's output can reach the other's input". It exists for one reader:
the chain analyzer's direct pair rule, which reports a chain when a dangerous pair has an edge.
Every other walker over graph edges reads `AttackKnowledgeGraph.structure_view()`, the graph
without co-resident edges. On a graph with no co-resident edge the view is the graph itself, so
every walker but the pair rule behaves as it did at base. Two fix rounds bounded one walker at a
time (cycle search, then the tool count) and a third walker (indirect search between two
50-tool agents that share a tool) still ran past 120 s. The rule removes the cause.

`ziran audit` finds a dangerous chain over a Claude Code agent's tools because `agent_chains`
links every ordered pair of the agent's tools with a `CAN_CHAIN_TO` edge: tools that live in one
agent share its context. `ziran scan` never added those edges. A LangChain agent with
`read_file` and `http_request` therefore showed no `data_exfiltration` chain in a scan, while
the same two tools in a Claude Code agent did in an audit. Only graph-shaped adapters, whose
structure import links tools through a shared state node, got chains.

After this change:

1. One knowledge-graph helper, `add_co_resident_tools`, adds the co-resident edges. `agent_chains`
   and the scan's capability discovery both use it.
2. The scan adds those edges only when the adapter's structure import linked no two tools,
   directly or through a state node (a tool reading its own channel links nothing). A LangGraph
   agent whose tools share a state channel keeps only its real edges. When the import reported
   no agents (LangChain, CrewAI, HTTP, MCP), all discovered tools form one co-resident set. When
   it reported agents (AutoGen, OpenAI Agents, other multi-agent topologies), each agent's own
   tools form one set, and the tools no agent lists form one more. A repeated discovery on the
   same graph (the pentest agent runs one campaign per step) adds the edges once.
3. A CrewAI crew's tools across all its agents form one co-resident set.
4. Only the direct pair rule reads co-resident edges. The walker list below names every walker
   and its view.
5. Chain analysis does not enumerate cycles on a graph that holds co-resident edges:
   `ToolChainAnalyzer.analyze(include_cycles=None)` defaults to skipping them when
   `graph.has_co_resident_tools()`. An explicit `include_cycles=True` runs them on the structure
   view.
6. The target decides how many tools it lists and what it calls them. n co-resident tools give
   n^2 edges and about n^2/4 chain findings, and each edge and finding copies both tool ids, so
   the output grows with n^2 times the id length (CWE-400, CWE-770). Three bounds hold it:
   - remote structured discovery (`HttpAgentAdapter._raw_to_capability`, the path of an MCP
     `tools/list`) cuts a tool's name and id to 100 characters, the length probe discovery
     already uses. A cut name ends in a hash of the whole name, so two long names stay apart;
   - `MAX_CO_RESIDENT_TOOLS = 100` in `structure_import.py` caps the tools across all
     co-resident sets of a scan;
   - `MAX_CO_RESIDENT_ID_CHARS = 20,000` caps the summed length of their ids, for adapters
     whose names no discovery step cuts.

   Above either cap no set gets edges. The skip is visible, not only a log line: the scan
   result carries a warning with both counts and both caps (`metadata.warnings`,
   `CampaignResult.warnings`), and the JSON result, the Markdown report, the HTML report and
   `ziran ci` (console, step summary and a `::warning` annotation) all show it.
7. The direct and indirect rules read one pair table (`_candidate_pairs`: each tool matched
   against each pattern role once). The direct rule used to match every pattern against every
   pair, which was the cost left at the cap (100 tools: 1.46 s in `analyze`, now 0.04 s).
8. `ziran audit` findings stay identical.

## Walkers over graph edges

Found by grep over `ziran/`, `benchmarks/` and `scripts/` for NetworkX calls (`nx.`),
`successors`, `predecessors`, `neighbors`, `has_edge`, `edges(`, `get_edge_data`, `subgraph`
and raw `graph.graph` access.

| Walker | Where | View |
|--------|-------|------|
| Direct pair rule: `has_edge` per tool pair | `ToolChainAnalyzer._find_direct_chains` | full graph. The one reader of co-resident edges |
| Indirect search: `has_edge` to skip a pair the pair rule reported | `ToolChainAnalyzer._find_indirect_chains` | full graph (it asks what the pair rule saw) |
| Indirect search: `nx.has_path`, `nx.all_simple_paths` (3 hops) | `ToolChainAnalyzer._find_indirect_chains` | structure view |
| Cycle search: `nx.descendants`, `nx.simple_cycles` | `ToolChainAnalyzer._find_chain_cycles` | structure view; off by default on a co-resident graph |
| Risk-score centrality: `nx.betweenness_centrality` | `ToolChainAnalyzer.analyze` | structure view; skipped on a co-resident graph over 800 nodes |
| Typed chains, unscoped shell tools | `_find_typed_chains`, `_find_unrestricted_execution` | read no edge |
| Lethal trifecta scopes: `out_edges` of agent nodes (added by spec 088) | `trifecta._scopes` | structure view |
| `nx.all_simple_paths` between two nodes | `AttackKnowledgeGraph.find_attack_paths` | structure view |
| `nx.all_simple_paths` from tools to findings and data | `AttackKnowledgeGraph.find_all_attack_paths` | structure view |
| `nx.all_simple_paths` between agents, `get_edge_data` | `AttackKnowledgeGraph.get_cross_agent_attack_paths` | structure view |
| `nx.betweenness_centrality` | `AttackKnowledgeGraph.get_critical_nodes` | structure view |
| `nx.betweenness_centrality` for node sizes | `AttackKnowledgeGraph._normalized_centrality` (from `export_state`) | structure view |
| Link check: `successors`, one state hop | `structure_import._links_tools` | structure view |
| Pentest graph tool | `pentesting/tools/graph.py` `analyze_graph` | calls `find_all_attack_paths`, `get_critical_nodes`, `analyze` and `export_state`: structure view through each |
| Scan result | `ResultBuilder.build` | calls `analyze`, `find_all_attack_paths`, `export_state`: as above |
| Marker scan: `edges(data=True)` | `AttackKnowledgeGraph.has_co_resident_tools` | full graph, one pass, no traversal |
| Serialisers: edge list, `nx.density`, phase edges | `export_state`, `_derive_node_phases`, `import_state`, `graph_storage.py`, `MultiAgentScanner._merge_agent_graph` | full graph, one pass, no traversal. The export keeps co-resident edges so the marker survives a reload |
| Renderers: draw each edge | `html_report.graph_state_to_vis`, `_cap_graph_state`; `visualizations` (`edges(data=True)`, `nx.spring_layout` on nodes with no phase) | full graph. They draw and place nodes, O(n^2) per layout step whatever the edge count; the Plotly visualiser has no production caller |
| Other graphs | `trace_analysis/analyzer_service.py`, `benchmarks/ground_truth/run.py` | their own graphs, never co-resident; they reach the walkers through `analyze` |

Node-only readers (`get_nodes_by_type`, `enables_links.py`, `pentesting/agent.py`,
`scanner.py` `add_node`) read no edge.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A flat agent's chain shows in the scan (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a LangChain agent with only `read_file` and `http_request` and no tool-to-tool
   structure, **When** `AgentScanner` discovers capabilities and `ToolChainAnalyzer` runs,
   **Then** a `data_exfiltration` chain from `tool_read_file` to `tool_http_request` is found
   (the renamed test in `tests/unit/test_langgraph_adapter.py`).
2. **Given** the same two tools on a CrewAI agent, on the HTTP adapter with tools from probe
   discovery, and on an MCP server's `tools/list`, **When** discovery runs, **Then** each yields
   the same `data_exfiltration` chain.

### User Story 2 - Graph-shaped agents keep their real edges (Priority: P1)

1. **Given** the LangGraph `exfil_graph` with a shared state channel, **When** discovery runs,
   **Then** no co-resident edge is added and `test_cross_node_chain_found` still finds its
   indirect path through `state:messages`.

### User Story 3 - Co-resident sets stay fast (Priority: P1)

1. **Given** a flat agent with 15 tools, **When** the scan's result builder analyses chains,
   **Then** cycle enumeration is skipped and the test finishes within its timeout.
2. **Given** two agents of 50 tools each that share one tool, **When** the scan result is built,
   **Then** it finishes in under 5 s, direct chains inside each agent are found and no chain
   crosses the agents.
3. **Given** a flat agent of 100 tools, **When** the result is built, **Then** it finishes in
   under 5 s and no walker other than the pair rule sees a co-resident edge (the test patches
   each NetworkX walker to raise on one).

### User Story 4 - The audit is unchanged (Priority: P1)

1. **Given** `ziran audit` on the Claude Code fixtures under `tests/fixtures/claude_code/`,
   **When** run at base and at head, **Then** its findings are identical.

### User Story 5 - The skip above the cap is visible (Priority: P1)

1. **Given** an MCP server whose `tools/list` has 101 tools, **When** the scan runs, **Then**
   the result JSON, the Markdown report, the HTML report and `ziran ci` output each show the
   co-resident skip warning with the count and the cap.

### Edge Cases

- An adapter that reports no structure, fails to, or reports a non-topology: the tools are
  treated as co-resident.
- Fewer than two tools: no edge is added.
- More than 100 tools across the co-resident sets, or more than 20,000 characters of ids: no
  co-resident edge at all, one log warning and one result warning, also when discovery runs
  twice on the graph. Exactly 100 tools, or exactly 20,000 characters, still link.
- An MCP `tools/list` of 100 tools with 20,000-character names: each id is 100 characters, all
  100 stay distinct, the 2,500 chains are found and the result is 3.9 MB (see Sizing).
- Two long tool names that differ only after the cut: the hash suffix keeps their ids apart.
- A tool name of exactly 100 characters, and any resource or skill id: untouched.
- Non-tool capabilities (skills, data access, CrewAI agent roles, probe lines that are not
  dangerous tools) are not part of the co-resident set.
- A graph with co-resident sets and a real path between two of their tools (built by hand; the
  scan never makes one): the indirect chain follows the real path only.
- A reloaded graph: the edges carry the `co_resident` marker through `export_state` and
  `import_state`, so the walkers still get the structure view.

## Requirements *(mandatory)*

- **FR-001**: `AttackKnowledgeGraph.add_co_resident_tools(tool_ids)` adds a `CAN_CHAIN_TO` edge
  for every ordered pair, marked `co_resident=True`; `has_co_resident_tools()` reports whether
  the graph holds one.
- **FR-002**: `agent_chains` builds its graph with that helper and keeps `include_cycles=False`.
- **FR-003**: `import_adapter_structure(adapter, graph, capabilities)` adds the co-resident edges
  over the tool-type capabilities when, after the import, no tool has an edge to another tool or
  to a state node another tool reads: one set for all tools when no agents were reported, else
  one set per agent plus one for the tools no agent lists. A graph that already holds
  co-resident edges gets none again.
- **FR-004**: `ToolChainAnalyzer.analyze` skips cycles by default when the graph holds
  co-resident edges, and runs them otherwise; an explicit `include_cycles` wins.
- **FR-005**: `scanner.py` stays at or under 750 lines (net zero change).
- **FR-006**: `AttackKnowledgeGraph.structure_view()` returns the graph without co-resident
  edges (the graph itself when it holds none). Every walker in the list above marked
  "structure view" reads it; only the direct pair rule reads co-resident edges.
- **FR-007**: at most `MAX_CO_RESIDENT_TOOLS` (100) tools and `MAX_CO_RESIDENT_ID_CHARS`
  (20,000) characters of ids across all co-resident sets; above either, no co-resident edges.
  Betweenness centrality in `analyze` is skipped on a co-resident graph over 800 nodes.
- **FR-008**: above a cap, `graph.warnings` gets one message with both counts and both caps.
  `ResultBuilder` copies it to `CampaignResult.metadata["warnings"]` (absent when empty), and
  the Markdown report, the HTML report, the `ziran ci` console output, its step summary and a
  `::warning` annotation (with `%`, CR and LF escaped) print each warning.
- **FR-009**: the direct and indirect rules take their pattern from one pair table that gives
  each ordered tool pair the first pattern it matches, the same answer as `_match_pattern`.

- **FR-010**: `HttpAgentAdapter._raw_to_capability` cuts a tool-type capability's name and id
  to 100 characters. A cut value keeps its first 91 characters and ends in `_` plus 8 hex
  digits of the SHA-256 of the whole value. Other capability types are untouched.

## Sizing

An MCP `tools/list` of 100 tools through `run_campaign(phases=[])`, by name length (the security
gate's `longname.py`; "before" is its reading at 89a527d):

| Name length | Result JSON | Graph export | Peak RSS | Run |
|-------------|-------------|--------------|----------|-----|
| 10 | 2.0 MB | 5.1 MB | 118 MB | 0.24 s |
| 2,000 | 3.9 MB (before 51.9 MB) | 9.3 MB | 124 MB (before 945 MB) | 0.28 s |
| 20,000 | 3.9 MB (before 503.7 MB) | 9.3 MB (before 1.1 GB) | 128 MB (before 5.8 GB) | 0.28 s (before 14.9 s) |

With one reconnaissance phase, which adds a graph snapshot, the 2,000 and 20,000 rows give a
7.3 MB result (before 94 MB at 2,000). The 20,000-character id cap is twice what 100 cut names
can reach, so it never trips on remote discovery; it bounds in-process adapters, where the
worst case under both caps is 100 tools of 200 characters.

## Assumptions

- A CrewAI crew shares task context between its agents (a task's output feeds the next task), so
  all its agents' tools form one co-resident set. Why: the adapter has no per-agent structure and
  the crew runs as one unit. Overturned by: a CrewAI adapter that reports per-agent structure
  through `discover_structure`, which then takes the graph-shaped path.
- In a topology with agents, only one agent's own tools are co-resident; a handoff (triage to
  billing with `query_database`, triage to mailer with `send_email`) yields no cross-agent
  chain. A tool two agents share sits in both sets and bridges nothing: indirect search does
  not read co-resident edges, so no chain crosses the agents through it, as at base. Why:
  chains across agents would over-report every team. Known gap, on the safe side: an AutoGen
  group chat shares its whole thread, so data can flow between its members' tools, and those
  cross-agent chains are not reported. Overturned by: a topology field that says the agents
  share context.
- Only `CapabilityType.TOOL` capabilities are co-resident. Why: skills and resources are not
  callable tools, and probe discovery files every line it does not classify as a dangerous tool
  as a skill. Overturned by: a chain pattern that needs a resource node as a source.
- The cap counts all sets together and stays at 100. Why: n tools give n^2 edges and about
  n^2/4 findings (100 tools: 9,900 edges, 2,500 findings, a 5.1 MB graph export), and the sets
  add up. The pattern match per pair is no longer the cost. Overturned by: a report that groups
  chain findings, after which the cap can rise.
- A remote tool name is cut at 100 characters. Why: probe discovery already cuts names there,
  and the scan only needs the name to match patterns and to label findings. A real tool whose
  name is longer gets a changed id, and the dynamic attack prompts name it by the cut form.
  Overturned by: real servers with longer tool names, after which the limit can rise (the id
  cap leaves room for 200).
- Only tool names are cut. Why: resource and skill ids form no pairs, so they grow the output
  only in step with the reply, as at base. Overturned by: a pairing rule over another type.
- The centrality bound in `analyze` stays. Why: a 100-tool flat graph holds 2,600 nodes once its
  2,500 chain findings are on it, and betweenness there takes 0.94 s, on every step of the
  pentest agent; with the bound `analyze` takes 0.02 s. Overturned by: a cheaper centrality.
- Path, cycle and centrality results leave out co-resident edges. Why: those edges say "could
  chain", which the chain findings already report; walking them multiplies paths and costs
  without adding a finding. Overturned by: a report that needs multi-tool paths to a data
  source on a flat agent.
- The warning is a line of text in `metadata.warnings`, not a gate failure. Why: at base a flat
  agent got no chain analysis at all, so the result is no worse than before, and the reader now
  sees that it was not analysed. Overturned by: an owner decision that an unanalysed agent must
  fail `ziran ci`.
- The renderers keep drawing co-resident edges. Why: they read each edge once and the cap bounds
  the count. Overturned by: the follow-up that hides or bundles them in the graph views.

## How this fails

- A later walker reads `graph.graph` and not `structure_view()`, and walks the complete sets
  again. The raising-patch test covers the five NetworkX walkers in use today; a walker built
  on another NetworkX function needs its name added to that test.
- A reader takes a scan with `metadata.warnings` for a full analysis: `ziran ci` still passes
  when the only gap is the skipped chain analysis.
- The pair table and `_match_pattern` (which cycle search still calls) drift apart. One test
  compares them pair by pair.
- Another remote discovery path adds tool capabilities without `_raw_to_capability` and brings
  long names back. The id cap in `structure_import.py` still skips the pairing and warns.

## Behaviour change

A flat-agent scan now reports chain findings it did not report before. The CI gate counts each
tool-composition chain as a finding (`ziran/application/cicd/gate.py`, the loop over
`dangerous_tool_chains`), so `ziran ci` on a flat agent with a dangerous tool pair can newly fail.
A scan of a target with more than 100 co-resident tools carries `metadata.warnings`.

## Out of scope

Chains steering the campaign (A-CHAIN-STEER), the lethal trifecta (A-TRIFECTA), README wording,
`benchmarks/ground_truth/run.py`, which keeps its own graph builder, and hiding co-resident
edges in the graph renderers.
