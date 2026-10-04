# Feature Specification: LangGraph state-graph native scanning

**Feature Branch**: `050-langgraph-native-scanning`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #393 (release 0.42.0, "faster scans, truer graphs" batch).
**Base**: `develop` @ cff8b7f (0.41.0 released).
**Siblings (parallel, separate worktrees)**: #288 / spec 049 (incremental scan cache: edits
`AgentScanner.run_campaign`, `phase_executor._run_attack`, adds `scan` options and a `cache`
command to `ziran/interfaces/cli/main.py`), #73 / spec 051 (`http_adapter._probe_discover` only),
#368 / spec 052 (web route tests only). Shared files with this feature:
`ziran/application/agent_scanner/scanner.py` (this feature edits `_discover_and_map_capabilities`
only, never `run_campaign`) and `ziran/interfaces/cli/main.py` (this feature edits the two
`--framework` `click.Choice` lists only).
**Input**: `LangChainAdapter` treats an agent as a flat bag of tools. A LangGraph agent is a graph
(`StateGraph`): named nodes, conditional edges and a shared typed state that tools read and
write. ZIRAN flattens that away, so a chain that is only possible because two nodes share state
(node A's tool writes untrusted content into state, node B's tool consumes it) is invisible to
the tool-chain analyzer.

## Facts this spec relies on (verified on `develop` @ cff8b7f with `uv sync --extra all`)

- Installed: `langgraph` 1.2.2, `langgraph-prebuilt` 1.1.0, `langchain-core` 1.4.8. `langchain`
  1.3.2 (the `langchain` extra) depends on `langgraph`, which depends on `langgraph-prebuilt`
  (`uv.lock`). No new dependency is needed.
- A compiled `StateGraph` is a `langgraph.pregel.Pregel` (`CompiledStateGraph`); the uncompiled
  `StateGraph` builder is not.
- `compiled.get_graph().edges` yields `Edge(source, target, data, conditional)`. For
  `add_conditional_edges("reader", route, {"sender": "sender", "end": END})` it yields
  `Edge("reader", "sender", data=None, conditional=True)` and
  `Edge("reader", "__end__", data="end", conditional=True)`: `data` carries the routing key only
  when it differs from the target name.
- `compiled.nodes[name]` is a `PregelNode`; `.bound` is the `ToolNode` itself for a
  `ToolNode([...])` node (also for the `tools` node built by `langchain.agents.create_agent`).
  `ToolNode.tools_by_name` maps tool name to `BaseTool`; the state key a `ToolNode` reads tool
  calls from and writes `ToolMessage`s to is the private attribute `_messages_key` (constructor
  argument `messages_key`, default `"messages"`).
- `PregelNode.channels` lists **every** state key for every node unless the node declares a
  narrower `input_schema` (then only that schema's keys), and a node's writers carry no per-key
  write set. Per-key read/write sets of arbitrary nodes therefore cannot be known statically.
- `ainvoke({"messages": [HumanMessage(text, id=...)]}, config={"configurable": {"thread_id":
  ...}})` works with and without a checkpointer (without one the `thread_id` is ignored; with one
  it is required). `add_messages` keeps the explicit message id, so the messages produced by one
  turn are those after the input message's id.
- `ToolChainAnalyzer._find_indirect_chains` searches `all_simple_paths(cutoff=3)` between every
  tool pair matching a dangerous pattern. A prototype graph with capabilities `tool_read_file`,
  `tool_http_request` and edges `tool -> state:messages -> tool` (both tools, both directions)
  yields exactly one chain: `data_exfiltration`, `chain_type="indirect"`, `graph_path ==
  ["tool_read_file", "state:messages", "tool_http_request"]`; the same two capabilities without
  the channel (what the scanner builds today) yield none.
- `AttackKnowledgeGraph.find_all_attack_paths` treats `DATA_SOURCE` and `VULNERABILITY` nodes as
  path targets, and `CampaignResult.success` (the "VULNERABLE" verdict) is true when any path
  exists. A harmless tool (`get_weather`) linked to a `DATA_SOURCE` channel produces the path
  `["tool_get_weather", "state:messages"]`; linked to an `AGENT_STATE` channel it produces none.

## User Scenarios & Testing *(mandatory)*

Shared fixture (all offline, no LLM): `exfil_graph()` builds and compiles a `StateGraph` over
`MessagesState` with
- `planner`: a plain function (scripted, no model). Turn logic on the current turn's messages: no
  tool result yet -> `AIMessage("", tool_calls=[read_file(path="notes.txt")])`; after the
  `read_file` result -> `AIMessage("", tool_calls=[http_request(url=...)])`; after the
  `http_request` result -> `AIMessage("done", usage_metadata={input_tokens: 3, output_tokens: 2,
  total_tokens: 5})`;
- `reader`: `ToolNode([read_file])`; `sender`: `ToolNode([http_request])` (both `@tool`
  functions returning fixed strings, no I/O);
- edges: `START -> planner`; `add_conditional_edges("planner", route, {"read": "reader",
  "send": "sender", "end": END})`; `reader -> planner`; `sender -> planner`.

`reader` and `sender` are two different nodes sharing the state key `messages`.

### User Story 1 - LangGraph nodes and edges become knowledge-graph entities (Priority: P1)

An operator points ZIRAN at a compiled `StateGraph`. The knowledge graph contains one entity per
graph node and one edge per graph edge, with the tools each node can call and the conditional
routes marked, instead of a flat tool list.

**Why this priority**: issue acceptance criteria 2 and 3 (distinct entities; unit-tested
extraction without an LLM).

**Independent Test**: `LangGraphAdapter(exfil_graph()).discover_structure()` and
`import_structure(AttackKnowledgeGraph(), topology)`.

**Acceptance Scenarios**:
1. **Given** `exfil_graph()`, **When** `discover_structure()` runs, **Then** the topology has
   agents `langgraph:planner` (role `router`, `capabilities == []`, `is_entry_point=True`),
   `langgraph:reader` (role `tool_node`, `capabilities == ["tool_read_file"]`) and
   `langgraph:sender` (role `tool_node`, `capabilities == ["tool_http_request"]`), all
   `framework == "langgraph"`; `entry_point_id == "langgraph:planner"`; no agent for
   `__start__` / `__end__`.
2. **Given** the same topology, **Then** its edges are exactly `planner -> reader` and
   `planner -> sender` (`conditional=True`, `branch_label == "read"` / `"send"`) and
   `reader -> planner`, `sender -> planner` (`conditional=False`, `branch_label is None`), all
   `delegation == FULL_CONTEXT`; edges from `__start__` or to `__end__` are not edges (the
   `START` target is the entry point; the `"end"` route is dropped).
3. **Given** the same topology, **Then** `state_channels == [StateChannel(name="messages",
   writers=["tool_http_request", "tool_read_file"], readers=["tool_http_request",
   "tool_read_file"])]`.
4. **Given** `import_structure(graph, topology)` on a graph that already holds the two
   capabilities, **Then** `graph.export_state()` contains nodes `langgraph:planner`,
   `langgraph:reader`, `langgraph:sender` with `node_type == "agent"`, a node `state:messages`
   with `node_type == "agent_state"`, `DELEGATES_TO` edges carrying `conditional` and
   `branch_label`, `USES_TOOL` edges `langgraph:reader -> tool_read_file` and
   `langgraph:sender -> tool_http_request`, and `ACCESSES_DATA` edges
   `tool_x -> state:messages` (`access == "write"`) and `state:messages -> tool_x`
   (`access == "read"`) for both tools.
5. **Given** that exported state, **When** `graph_state_to_vis` (the HTML report's mapper, which
   shares `graph_style.json` with the web UI) runs, **Then** the three agent nodes and the
   `delegates_to` edges are present with their own node/edge types (no new type, no style
   change).
6. **Given** a `ToolNode` built with `messages_key="scratch"`, **Then** its tools are on a
   channel named `scratch`, not `messages`.
7. **Given** a node whose runnable is itself a compiled graph, **Then** it is an agent with role
   `subgraph` and no capabilities (no recursion).

### User Story 2 - A state-mediated cross-node chain is a finding the flat adapter misses (Priority: P1)

**Why this priority**: issue acceptance criterion 1; the reason the feature exists.

**Independent Test**: `AgentScanner` with the LangGraph adapter vs. `LangChainAdapter` over the
same two tool objects, then `ToolChainAnalyzer` (what `ResultBuilder` runs).

**Acceptance Scenarios**:
1. **Given** `AgentScanner(adapter=LangGraphAdapter(exfil_graph()), attack_library=...)`,
   **When** `_discover_and_map_capabilities()` runs, **Then**
   `ToolChainAnalyzer(scanner.graph).analyze()` contains a chain with
   `vulnerability_type == "data_exfiltration"`, `chain_type == "indirect"`,
   `tools == ["tool_read_file", "tool_http_request"]` and
   `graph_path == ["tool_read_file", "state:messages", "tool_http_request"]`.
2. **Given** `LangChainAdapter(SimpleNamespace(tools=[read_file, http_request]))` (the same
   `BaseTool` objects as flat capabilities), **When** the same two steps run, **Then** no chain
   with `vulnerability_type == "data_exfiltration"` is reported.
3. **Given** `run_campaign(phases=[ScanPhase.RECONNAISSANCE], coverage=CoverageLevel.ESSENTIAL)`
   with the LangGraph adapter, **Then** `result.dangerous_tool_chains` contains that
   `data_exfiltration` chain and `result.metadata["graph_stats"]["node_types"]["agent"] == 3`.
4. **Given** an adapter that only has harmless tools in a `ToolNode`, **Then** importing its
   structure adds no attack path (`find_all_attack_paths()` is unchanged) and no chain, so the
   scan verdict is not flipped by the structure import alone.

### User Story 3 - LangGraph agents can be scanned from the CLI (Priority: P1)

**Acceptance Scenarios**:
1. **Given** a file exposing a compiled graph as `graph`, **When**
   `ziran discover --framework langgraph <file>` runs, **Then** it exits `0` and lists
   `tool_read_file` and `tool_http_request` as dangerous.
2. **Given** `ziran scan --framework langgraph --agent-path <file>`, **Then** `langgraph` is an
   accepted `--framework` value (click does not reject it) and the adapter is a
   `LangGraphAdapter`.
3. **Given** `load_agent_adapter("langgraph", path)`, **Then** it loads the object named `graph`
   from `path` and returns `LangGraphAdapter(graph)`; with langgraph missing it raises
   `ImportError("LangGraph not installed. Run: uv sync --extra langchain\n...")`.
4. **Given** `ziran init` (interactive), **Then** `langgraph` is offered as a framework.
5. **Given** `LangGraphAdapter(builder)` where `builder` is an uncompiled `StateGraph` (or any
   non-`Pregel` object), **Then** it raises `TypeError` naming `.compile()`.

### User Story 4 - Invoking the graph reports tool calls and tokens (Priority: P1)

**Acceptance Scenarios**:
1. **Given** `exfil_graph()`, **When** `invoke("hello")` runs, **Then** `content == "done"`,
   `tool_calls == [{"tool": "read_file", "input": {"path": "notes.txt"}, "output": <read_file
   result>}, {"tool": "http_request", "input": {...}, "output": <http_request result>}]` (pairs
   matched by `tool_call_id`), and `prompt_tokens == 3`, `completion_tokens == 2`,
   `total_tokens == 5` (sum of `usage_metadata` of the turn's `AIMessage`s; 0 when absent).
2. **Given** the same graph compiled with `InMemorySaver()`, **When** `invoke` runs twice,
   **Then** each response contains only that turn's tool calls and content (messages after the
   turn's input message id), and `reset_state()` switches to a new `thread_id` so the next turn
   starts with an empty history.
3. **Given** any invoke, **Then** `get_state().conversation_history` gains the user message and
   the assistant content, and `observe_tool_call` appends to the observed calls.

### User Story 5 - Documented (Priority: P2)

**Acceptance Scenarios**:
1. **Given** `docs/guides/adapters.md`, **Then** it has a `### LangGraph` section: constructor,
   extra (`uv sync --extra langchain`), the `ziran scan|discover --framework langgraph` commands,
   what is mapped (nodes, edges, conditional routes, `ToolNode` tools, state channels), the
   "possible via shared state" semantics and the coverage limits in Edge Cases; and one complete
   `python` code block that builds a graph without any LLM and exposes it as `graph`.
2. **Given** that code block written to a file, **When** `load_agent_adapter("langgraph",
   file)` runs, **Then** capability discovery and one `invoke` succeed offline.

### Edge Cases
- **Coverage of tools**: only tools held by a `ToolNode` are discovered (that is where
  LangGraph exposes them). Tools bound inside an LLM node with `bind_tools(...)`, called from a
  plain function node, or captured in closures are not introspectable and are not discovered;
  such nodes appear as agents without capabilities. Documented as partial coverage.
- **State-channel precision**: data-flow edges are drawn only for `ToolNode` tools, on the
  `ToolNode`'s messages key, both directions (a `ToolNode` reads tool calls from that key and
  writes tool results to it). `PregelNode.channels` is never used to draw data-flow edges (on
  langgraph 1.2.x it lists every state key for every node, and writers carry no per-key write
  set), so there is no coarse all-keys fallback and no node x key fan-out. A chain through a
  channel means data **can** flow between the tools via shared state (in practice, through the
  model that reads one tool's result and writes the next tool call); it is reported as a latent
  composition finding (`finding_source="composition"`), never as a confirmed exploit.
- **Same-node pairs**: two dangerous tools in one `ToolNode` share its channel too, so their
  chain is also reported; this is the same shared-state flow and is intended.
- **Tool in several `ToolNode`s**: one capability (`tool_<name>`, first definition wins), one
  `USES_TOOL` edge per node, listed once per channel.
- **Fan-out**: the import adds `2 x (tool, channel)` data-flow edges plus one `USES_TOOL` edge
  per (node, tool): linear in the number of tools. Paths through a channel make
  `find_all_attack_paths` grow by up to a factor of the number of tools sharing that channel;
  it keeps its existing `max_paths=10_000` cap. `DELEGATES_TO` edges between nodes add cycles
  among agent nodes, exponential in the number of nodes of a densely routed graph.
  No such cycle can hold a tool (tools have no edges back to
  agents), so `ToolChainAnalyzer` enumerates cycles only on the sub-graph of tools and their
  descendants; this is exact and drops no findings.
- **Channel node type**: channels are `AGENT_STATE` nodes (shared agent state), not
  `DATA_SOURCE`: a `DATA_SOURCE` channel would be an attack-path target and turn every LangGraph
  agent with any tool into a "VULNERABLE" verdict (see Facts).
- **`START` / `END`**: not agents. The targets of `START` edges are entry points; routes to `END`
  are not represented.
- **Sub-graphs**: a node that is a compiled graph is an agent with role `subgraph`; its inner
  nodes and tools are not imported (deferred).
- **Conditional edges** are attributes (`conditional`, `branch_label`) on the `DELEGATES_TO`
  edges only; no campaign strategy targets a route yet (deferred).
- **Invocation contract**: the adapter sends `{"messages": [HumanMessage(...)], **kwargs}`; a
  graph whose state has no `messages` key fails in LangGraph and the attack is recorded as an
  error by the existing executor. Graphs that pause with `interrupt()` return what they produced
  before the interrupt; they are not resumed. Recursion-limit and other LangGraph errors
  propagate to the existing executor error handling.
- **Structure discovery failure** (`discover_structure` raises, e.g. `get_graph()` fails):
  logged as `structure_discovery_failed` (exception type and message only), the scan continues
  with the flat capability graph. A non-`MultiAgentTopology` return value is ignored.
- **Other adapters**: the port hook defaults to `None`; every existing adapter and
  `MockAgentAdapter` are untouched and produce exactly today's graph. Topology entries that
  reference unknown agent ids or capability ids not in the graph are skipped (no bare nodes are
  created).

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (port hook)**: `BaseAgentAdapter.discover_structure()` is a non-abstract `async`
  method returning `MultiAgentTopology | None`, default `None`.
- **FR-002 (domain model)**: `AgentEdge` gains `conditional: bool = False` and
  `branch_label: str | None = None`; new `StateChannel(name, writers, readers)`;
  `MultiAgentTopology` gains `state_channels: list[StateChannel] = []`. All additive with
  defaults; existing construction and serialisation unchanged otherwise.
- **FR-003 (adapter)**: `LangGraphAdapter` in `ziran/infrastructure/adapters/langgraph_adapter.py`
  implements `BaseAgentAdapter` for a compiled LangGraph graph: invoke (US4), capability
  discovery from `ToolNode`s reusing the LangChain adapter's tool-to-capability mapping and the
  shared `is_dangerous` classifier, structure discovery (US1.1-US1.3, US1.6, US1.7); rejects a
  non-`Pregel` graph with `TypeError` (US3.5). Imports of langgraph/langchain-core happen when
  the module is imported (lazily, through the factory).
- **FR-004 (graph import)**: `import_structure(graph, topology)` in the new module
  `ziran/application/agent_scanner/structure_import.py` maps the topology onto the
  `AttackKnowledgeGraph` as in US1.4 using the existing `add_agent_node`,
  `add_delegation_edge`, `add_agent_state` and `add_edge` helpers;
  `import_adapter_structure(adapter, graph)` calls the hook, handles failures as in Edge Cases
  and calls `import_structure`.
- **FR-005 (scanner wiring)**: `AgentScanner._discover_and_map_capabilities` calls
  `import_adapter_structure(self.adapter, self.graph)` after the capabilities are added;
  `scanner.py` diff is net-zero or negative and `run_campaign` is not touched.
- **FR-006 (chain finding)**: no change to `ResultBuilder` or `AttackKnowledgeGraph`; the
  state-channel edges alone make US2.1 and US2.3 true and US2.2 / US2.4 stay false.
  `ToolChainAnalyzer` changes in two small ways only: cycle enumeration is limited to tools
  and their descendants (see Edge Cases > Fan-out), and an indirect chain through an
  `AGENT_STATE` node says "possible via shared state" in its description.
- **FR-007 (factory + CLI)**: `load_agent_adapter("langgraph", path)` (US3.3); `langgraph` added
  to the `--framework` choices of `scan` and `discover` and to `init_command._FRAMEWORKS`;
  `docs/reference/cli.md` framework lists mention `langgraph`.
- **FR-008 (docs)**: US5.
- **FR-009 (size guards)**: `scanner.py` stays <= 750 lines (net-zero diff); the new sub-module
  is <= 400 lines; `tests/unit/application/test_scanner_size.py` passes unmodified.
- **FR-010 (no regressions)**: every existing test passes unmodified; no new runtime
  dependency; `pyproject.toml` and `uv.lock` unchanged.

### Assumptions (recorded, most conservative reading)
- "Conditional edges represented so campaign strategies can target specific routes" is narrowed
  to representation (attributes on the edges); route-targeting strategies are deferred (release
  planner).
- "Reuse the delegation-edge modelling from #163 for sub-graph handoffs": node-to-node edges use
  `DELEGATES_TO`; recursion into sub-graphs is deferred.
- "Model the shared state channels as data-flow nodes": channels are `AGENT_STATE` nodes, not
  `DATA_SOURCE` as the planner brief suggested, because a `DATA_SOURCE` channel flips the scan
  verdict for every LangGraph agent (Facts, Edge Cases). The chain analyzer is node-type agnostic
  for intermediates, so the finding is the same.
- "The flat LangChain adapter misses it on the same agent" is proven with `LangChainAdapter`
  over the same tool objects (a LangGraph graph cannot be fed to `LangChainAdapter`, which needs
  an `AgentExecutor`).
- "Graph nodes/edges visible in the HTML report / UI graph" is proven through
  `graph_state_to_vis` and the shared `graph_style.json` node/edge types; the web UI is not
  rendered in this environment.
- LangGraph rides with the existing `langchain` extra (transitive via `langchain>=1.0`); no
  `langgraph` extra, no explicit pin.
- Node roles: `tool_node` (a `ToolNode`), `subgraph` (a compiled graph), `router` (has a
  conditional outgoing edge), `worker` (anything else).

### Key Entities
- **StateChannel** (`name`, `writers`, `readers`): domain Pydantic model, capability ids.
- **AgentEdge** (+ `conditional`, `branch_label`), **MultiAgentTopology** (+ `state_channels`).
- **LangGraphAdapter**: infrastructure adapter.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US5 pass as tests with no network, no LLM and no API keys
  (`pytest.importorskip("langgraph")` where langgraph is needed).
- **SC-002**: the US2.1 / US2.2 pair proves a cross-node `data_exfiltration` chain that the flat
  adapter does not report on the same tools.
- **SC-003**: `tests/unit/application/test_scanner_size.py` passes; `git diff --numstat` on
  `scanner.py` shows deletions >= insertions; `run_campaign` is absent from the diff.
- **SC-004**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-005 (unverified offline)**: behaviour against a real LLM-driven LangGraph agent (that a
  model actually forwards one tool's output into the next tool call), and the visual rendering
  in the web UI, are not exercised; the PR says so.
