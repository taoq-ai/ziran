# Feature Specification: `ziran scan` finds tool chains on flat agents

**Feature Branch**: `fix/086-flat-agent-chains`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-FLAT-CHAINS (goal G-a), issue #536 row 1.
**Base**: `develop` @ 3b0589a.

## The promise in our own words

`ziran audit` finds a dangerous chain over a Claude Code agent's tools because `agent_chains`
links every ordered pair of the agent's tools with a `CAN_CHAIN_TO` edge: tools that live in one
agent share its context, so the output of one can reach the input of another. `ziran scan` never
adds those edges. A LangChain agent with `read_file` and `http_request` therefore shows no
`data_exfiltration` chain in a scan, while the same two tools in a Claude Code agent do in an
audit. Only graph-shaped adapters, whose structure import links tools through a shared state
node, get chains today.

After this change:

1. One knowledge-graph helper adds the co-resident edges. `agent_chains` and the scan's capability
   discovery both use it.
2. The scan adds those edges between every pair of discovered tools only when the adapter's
   structure import linked no two tools, directly or through a state node. A LangGraph agent
   whose tools share a state channel keeps only its real edges.
3. A CrewAI crew's tools across all its agents form one co-resident set.
4. Chain analysis never enumerates cycles on a graph that holds co-resident edges: the scan's
   result builder and the audit both skip it, since cycle enumeration is exponential on the
   complete graph those edges form.
5. Attack-path enumeration (`find_all_attack_paths`) ignores co-resident edges. On a complete
   tool graph every ordering of tools is a simple path, so a six-tool mock scan went from 9
   critical paths to 2,678; with the filter it reports 13 (the 9 plus one path from each tool
   to each of the two chain findings).
6. `ziran audit` findings stay identical.

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

### User Story 3 - The complete graph stays fast (Priority: P1)

1. **Given** a flat agent with 15 tools, **When** the scan's result builder analyses chains,
   **Then** cycle enumeration is skipped and the test finishes within its timeout.

### User Story 4 - The audit is unchanged (Priority: P1)

1. **Given** `ziran audit` on the Claude Code fixtures under `tests/fixtures/claude_code/`,
   **When** run at base and at head, **Then** its findings are identical.

### Edge Cases

- An adapter that reports no structure, fails to, or reports a non-topology: the tools are
  treated as co-resident.
- Fewer than two tools: no edge is added.
- Non-tool capabilities (skills, data access, CrewAI agent roles, probe lines that are not
  dangerous tools) are not part of the co-resident set.
- A resumed scan: the edges carry a `co_resident` marker that survives the checkpoint's graph
  export and import, so the result builder still skips cycles.

## Requirements *(mandatory)*

- **FR-001**: `AttackKnowledgeGraph.add_co_resident_tools(tool_ids)` adds a `CAN_CHAIN_TO` edge
  for every ordered pair, marked `co_resident=True`; `has_co_resident_tools()` reports whether
  the graph holds one.
- **FR-002**: `agent_chains` builds its graph with that helper and keeps `include_cycles=False`.
- **FR-003**: `import_adapter_structure(adapter, graph, capabilities)` adds the co-resident edges
  over the tool-type capabilities when, after the import, no tool has an edge to another tool or
  to a state node another tool reads.
- **FR-004**: `ResultBuilder.build` runs `analyze(include_cycles=False)` when the graph holds
  co-resident edges, and with cycles otherwise.
- **FR-005**: `scanner.py` stays at or under 750 lines (net zero change).
- **FR-006**: `find_all_attack_paths` enumerates over a view of the graph without co-resident
  edges.

## Assumptions

- A CrewAI crew shares task context between its agents (a task's output feeds the next task), so
  all its agents' tools form one co-resident set. Why: the adapter has no per-agent structure and
  the crew runs as one unit. Overturned by: a CrewAI adapter that reports per-agent structure
  through `discover_structure`, which then takes the graph-shaped path.
- AutoGen and OpenAI Agents topologies carry no state channels, so their import links no two
  tools and their tools become co-resident. Why: the rule in the plan item is "linked no two
  tools"; a group chat shares its whole thread and a handoff passes full context, so data does
  flow between those tools. Overturned by: the owner wanting those adapters to keep only their
  real edges, which is a one-line check on the topology in `import_adapter_structure`.
- Only `CapabilityType.TOOL` capabilities are co-resident. Why: skills and resources are not
  callable tools, and probe discovery files every line it does not classify as a dangerous tool
  as a skill. Overturned by: a chain pattern that needs a resource node as a source.
- Critical paths leave out co-resident edges. Why: those edges say "could chain", which the
  chain findings already report; walking them only multiplies paths up to the 10,000 cap.
  Overturned by: a report that needs multi-tool paths to a data source.

## Out of scope

Chains steering the campaign (A-CHAIN-STEER), the lethal trifecta (A-TRIFECTA), README wording,
and `benchmarks/ground_truth/run.py`, which keeps its own graph builder.
