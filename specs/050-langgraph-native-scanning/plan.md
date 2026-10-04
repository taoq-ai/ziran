# Implementation Plan: LangGraph state-graph native scanning

**Branch**: `050-langgraph-native-scanning` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #393 (release 0.42.0) | **Base**: `develop` @ cff8b7f
**Parallel siblings**: #288 / spec 049 edits `AgentScanner.run_campaign`, the scanner import block
(likely a `scan_cache` import) and `scan` options + a `cache` command in `main.py`. This plan
touches `scanner.py` only in its import block (one line) and in `_discover_and_map_capabilities`,
and `main.py` only in the two `--framework` `click.Choice` lists. An adjacent-import conflict
with #288 in `scanner.py` is resolved by keeping both lines in isort order.

## Summary
A new `LangGraphAdapter` wraps a compiled LangGraph graph. Besides `invoke` and capability
discovery (tools of every `ToolNode`), it implements a new optional port hook,
`BaseAgentAdapter.discover_structure()`, returning the existing domain `MultiAgentTopology`
(extended with conditional-edge attributes and `StateChannel`s). A new agent_scanner
sub-module imports that topology into the `AttackKnowledgeGraph` with the existing helpers:
graph nodes as `AGENT` nodes, graph edges as `DELEGATES_TO` edges, node -> tool `USES_TOOL`
edges, and one `AGENT_STATE` node per `ToolNode` messages key with `tool -> state -> tool`
`ACCESSES_DATA` edges. Those two-hop paths are exactly what `ToolChainAnalyzer`'s indirect-chain
search (cutoff 3) already finds, so a `read_file` in one node and an `http_request` in another
become a `data_exfiltration` composition finding with no analyzer change. Every other adapter
keeps the default `None` and today's graph.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (domain models), existing `AttackKnowledgeGraph` (NetworkX) and `ToolChainAnalyzer`, `langgraph` 1.2.x + `langchain-core` via the existing `langchain` extra (transitive). No new dependencies.
(Per `uv.lock`: `langchain` 1.3.2 -> `langgraph` -> `langgraph-prebuilt`; no `pyproject.toml` or
`uv.lock` change.)
**Storage**: N/A — in-memory knowledge graph only.
**Testing**: pytest (`@pytest.mark.unit`), `pytest.importorskip("langgraph")` in tests that need
it, real compiled `StateGraph` fixtures whose "model" node is a scripted Python function (no LLM,
no network, no keys); `MockAgentAdapter` / `shared_attack_library` from `tests/conftest.py`;
Click `CliRunner`.
**Target Platform**: `ziran scan|discover --framework langgraph`; `AgentScanner` with a
`LangGraphAdapter`.
**Project Type**: single Python package.
**Performance Goals**: structure import is O(nodes + edges + tools); data-flow edges are linear in
the number of tools (2 per (tool, channel)).
**Constraints**: `scanner.py` is 750 lines (cap 750, `test_scanner_size.py`): net-zero diff.
New sub-module <= 400 lines. mypy strict, line length 100. CI's mypy job runs with
`uv sync --group dev` (no extras), where `langgraph.*` / `langchain_core.*` are missing and
covered by the existing `ignore_missing_imports` override; locally (extras installed) langgraph
ships `py.typed`. The adapter therefore types LangGraph objects as `Any` at its boundary and must
pass `uv run mypy ziran/` in both environments.
**Measured today** (`wc -l`, `develop` @ cff8b7f): `scanner.py` 750, `adapter.py` 158,
`multi_agent.py` 221, `langchain_adapter.py` 253, `factories.py` 302, `init_command.py` 162,
`docs/guides/adapters.md` 78.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Domain: `StateChannel` + additive fields in `ziran/domain/entities/multi_agent.py`; the port hook in `ziran/domain/interfaces/adapter.py` (imports the domain model under `TYPE_CHECKING`). Infrastructure: `LangGraphAdapter` implements the port and imports only domain + LangGraph + the LangChain adapter's helper (same layer). Application: `structure_import.py` consumes the port and the domain model and writes the application `AttackKnowledgeGraph`; it never imports infrastructure. The factory (application, already the place that lazily imports adapters) and the CLI (interfaces) wire it. |
| II. Type safety | PASS | All new data is Pydantic; every function annotated; LangGraph objects are `Any` at the boundary (as `LangChainAdapter` does). |
| III. Tests | PASS | Test-first tasks; unit tests for the domain additions, the import module (hand-built topologies, `MockAgentAdapter`), the adapter (real offline graphs), the scanner wiring, the factory, the CLI and the docs example. Existing tests unmodified. |
| IV. Async-first | PASS | `discover_structure` and `invoke` are async (`ainvoke`); introspection itself does no I/O. |
| V. Extensibility | PASS | A new framework via a new `BaseAgentAdapter`; the hook is optional with a `None` default, so no existing adapter changes. |
| VI. Simplicity | PASS | Reuses `MultiAgentTopology`/`AgentNode`/`AgentEdge`, `add_agent_node`/`add_delegation_edge`/`add_agent_state`/`add_edge`, `ToolChainAnalyzer` unchanged, the LangChain tool-to-capability mapping, `is_dangerous`, `_load_python_object`. No new node/edge type, no UI or report change, no analyzer change, no extra. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #393 implementer. Names, signatures, ids, roles, attribute keys and log events
MUST NOT change without updating this file.

### 1. `ziran/domain/entities/multi_agent.py` (edit, additive)

```python
class AgentEdge(BaseModel):
    ...  # existing fields unchanged
    conditional: bool = Field(
        default=False,
        description="Edge is taken only when a routing function selects it "
        "(e.g. a LangGraph conditional edge)",
    )
    branch_label: str | None = Field(
        default=None,
        description="Routing key that selects this edge, when it differs from the target name",
    )


class StateChannel(BaseModel):
    """A shared-state key through which tools can pass data to each other (spec 050)."""

    name: str = Field(description="State key, e.g. 'messages'")
    writers: list[str] = Field(
        default_factory=list, description="Capability ids whose results are written to this key"
    )
    readers: list[str] = Field(
        default_factory=list, description="Capability ids whose inputs are read from this key"
    )


class MultiAgentTopology(BaseModel):
    ...  # existing fields unchanged
    state_channels: list[StateChannel] = Field(
        default_factory=list, description="Shared state channels between tools (spec 050)"
    )
```
`StateChannel` is defined before `MultiAgentTopology`. `import_topology` and the multi-agent
scanner are not changed (they ignore the new fields).

### 2. `ziran/domain/interfaces/adapter.py` (edit)

```python
if TYPE_CHECKING:
    ...
    from ziran.domain.entities.multi_agent import MultiAgentTopology

class BaseAgentAdapter(ABC):
    ...
    async def discover_structure(self) -> MultiAgentTopology | None:
        """Return the agent's internal graph structure, if the framework exposes one.

        Override in adapters for graph-shaped frameworks (e.g. LangGraph). The scanner imports
        the returned topology into the knowledge graph next to the discovered capabilities.
        Default: ``None`` (no structure; the flat capability graph is used).
        """
        return None
```
Non-abstract; placed after `discover_capabilities`.

### 3. `ziran/infrastructure/adapters/langchain_adapter.py` (edit, behaviour-preserving)

Extract the body of the `for tool in tools:` loop of `discover_capabilities` verbatim into a
module-level function and call it from the loop:
```python
def tool_to_capability(tool: Any) -> AgentCapability:
    """Map a LangChain tool to an AgentCapability (shared with the LangGraph adapter)."""
```
(`id=f"tool_{tool.name}"`, `name`, `type=CapabilityType.TOOL`, `description`, `parameters`
`{"schema": args_schema.model_json_schema()}` or `{}`, `dangerous=_is_dangerous_tool(tool.name)`,
`requires_permission=getattr(tool, "requires_confirmation", False)`.) Existing LangChain tests
pass unmodified.

### 4. `ziran/infrastructure/adapters/langgraph_adapter.py` (new)

```python
"""LangGraph adapter (spec 050). Requires the ``langchain`` extra (LangGraph rides with it)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ziran.domain.entities.multi_agent import (
    AgentEdge, AgentNode, DelegationPattern, MultiAgentTopology, StateChannel,
)
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.infrastructure.adapters.langchain_adapter import tool_to_capability
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from ziran.domain.entities.capability import AgentCapability

try:
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langgraph.prebuilt import ToolNode
    from langgraph.pregel import Pregel
except ImportError as e:
    raise ImportError(
        "LangGraph is required for LangGraphAdapter. Install it with: uv sync --extra langchain"
    ) from e

FRAMEWORK = "langgraph"
NODE_ID_PREFIX = "langgraph:"          # AgentNode.id = NODE_ID_PREFIX + graph node name
_START, _END = "__start__", "__end__"


class LangGraphAdapter(BaseAgentAdapter):
    def __init__(self, graph: Any) -> None:
        """graph: a compiled LangGraph graph (``StateGraph(...).compile()``).

        Raises TypeError("LangGraphAdapter expects a compiled graph (a langgraph Pregel); "
        "call .compile() on the StateGraph builder, got <type name>") when
        ``not isinstance(graph, Pregel)``.
        """
        self.graph = graph
        self._thread_id: str = uuid4().hex
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse: ...
    async def discover_capabilities(self) -> list[AgentCapability]: ...
    async def discover_structure(self) -> MultiAgentTopology: ...
    def get_state(self) -> AgentState: ...
    def reset_state(self) -> None: ...
    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None: ...
```

Behaviour:
- **`invoke`**: `human = HumanMessage(message, id=uuid4().hex)`;
  `out = await self.graph.ainvoke({"messages": [human], **kwargs},
  config={"configurable": {"thread_id": self._thread_id}})`; `msgs = out["messages"]`; the turn's
  messages are `msgs[i + 1:]` where `msgs[i].id == human.id` (all of `msgs` if not found).
  Tool calls: for each `AIMessage` in turn order, for each `tool_call`:
  `{"tool": tc["name"], "input": tc["args"], "output": <str(content) of the ToolMessage whose
  tool_call_id == tc["id"], or "">}`; each is also appended to the observed calls. Content: `.text`
  of the last `AIMessage` of the turn, `""` when none. Tokens: sums of
  `usage_metadata["input_tokens"|"output_tokens"|"total_tokens"]` over the turn's `AIMessage`s
  (missing metadata counts 0). History gains `{"role": "user", ...}` and
  `{"role": "assistant", ...}`. `metadata == {"framework": "langgraph", "turn_messages": <len of
  the turn's messages>}`. LangGraph exceptions propagate.
- **`discover_capabilities`**: for each `PregelNode` in `self.graph.nodes.values()` (insertion
  order) whose `.bound` is a `ToolNode`, for each tool in `bound.tools_by_name.values()`:
  `tool_to_capability(tool)`; deduplicated by capability id (first wins). Logs
  `langgraph_tools_discovered` (`tool_count`, `dangerous_count`).
- **`discover_structure`**: with `nodes = self.graph.nodes` and
  `edges = self.graph.get_graph().edges`:
  - one `AgentNode` per node name other than `__start__`: `id=NODE_ID_PREFIX + name`,
    `name=name`, `framework="langgraph"`, `capabilities` = sorted `tool_<name>` ids of its
    `ToolNode` (else `[]`), `is_entry_point` = name is the target of an edge from `__start__`,
    `role` = `"tool_node"` (bound is a `ToolNode`), else `"subgraph"` (bound is a `Pregel`),
    else `"router"` (the node has a conditional outgoing edge), else `"worker"`;
  - one `AgentEdge` per drawable edge whose source is not `__start__` and target is not
    `__end__`: `source_id`/`target_id` prefixed, `delegation=DelegationPattern.FULL_CONTEXT`,
    `conditional=edge.conditional`, `branch_label=None if edge.data is None else str(edge.data)`;
  - `state_channels`: one `StateChannel` per distinct `ToolNode` messages key
    (`getattr(bound, "_messages_key", "messages")`, the private attribute behind the
    `messages_key` constructor argument; default documented), `writers == readers ==` sorted
    capability ids of all `ToolNode`s with that key; channels sorted by name;
  - `entry_point_id` = id of the first entry-point agent (or `None`),
    `metadata == {"framework": "langgraph"}`, `topology_type` left at its default.
  `PregelNode.channels` is not read (spec Edge Cases: state-channel precision).
- **`get_state`**: `AgentState(session_id=self._thread_id,
  conversation_history=list(history))`.
- **`reset_state`**: clears history and observed calls; `self._thread_id = uuid4().hex`.

### 5. `ziran/application/agent_scanner/structure_import.py` (new, <= 400 lines; ~80 expected)

```python
"""Import an adapter-reported agent structure into the knowledge graph (spec 050)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.graph import EdgeType
from ziran.domain.entities.multi_agent import MultiAgentTopology
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

STATE_NODE_PREFIX = "state:"     # knowledge-graph node id = STATE_NODE_PREFIX + channel name


async def import_adapter_structure(
    adapter: BaseAgentAdapter, graph: AttackKnowledgeGraph
) -> MultiAgentTopology | None:
    """Call adapter.discover_structure() and import the result; never raises.

    Exception -> logger.warning("structure_discovery_failed", error=f"{type(e).__name__}: {e}"),
    return None. None -> return None. Not a MultiAgentTopology -> logger.warning(
    "structure_discovery_ignored", type=<type name>), return None. Otherwise
    import_structure(graph, topology) and return the topology.
    """


def import_structure(graph: AttackKnowledgeGraph, topology: MultiAgentTopology) -> None:
    """Map *topology* onto *graph* (nodes, edges, tool links, state channels)."""
```

`import_structure` writes, in this order:
1. per agent: `graph.add_agent_node(agent.id, role=agent.role, metadata={"name": agent.name,
   "framework": agent.framework, "is_entry_point": agent.is_entry_point,
   "capabilities": list(agent.capabilities)})`;
2. per edge whose `source_id` and `target_id` are both topology agent ids:
   `graph.add_delegation_edge(src, tgt, delegation_pattern=edge.delegation.value,
   metadata={"conditional": edge.conditional, "branch_label": edge.branch_label})`; other edges
   are skipped;
3. per agent, per capability id present in `graph.graph`:
   `graph.add_edge(agent.id, cap_id, EdgeType.USES_TOOL)`; unknown ids skipped;
4. per channel with at least one writer or reader present in `graph.graph`:
   `node = STATE_NODE_PREFIX + channel.name`; `graph.add_agent_state(node, {"name":
   f"state.{channel.name}", "channel": channel.name, "writers": [...], "readers": [...],
   "description": "Shared state: data written here by one tool can reach the tools that read
   it"})` (lists filtered to present ids); per present writer
   `graph.add_edge(writer, node, EdgeType.ACCESSES_DATA, {"access": "write"})`; per present
   reader `graph.add_edge(node, reader, EdgeType.ACCESSES_DATA, {"access": "read"})`;
5. `logger.info("structure_imported", agents=..., edges=<delegation edges added>,
   channels=<channels added>)`.

No other node or edge is created. `AttackKnowledgeGraph`, `ToolChainAnalyzer`, `ResultBuilder`,
`graph_style.json`, the HTML report and the UI are not changed.

### 6. `ziran/application/agent_scanner/scanner.py` (edit, net 0 lines; today 750)

| Where | Change | Lines |
|---|---|---|
| import block, after the two `result_builder` imports (isort order) | `from ziran.application.agent_scanner.structure_import import import_adapter_structure` (85 chars) | +1 |
| `_discover_and_map_capabilities`, after the `for cap in capabilities:` loop, before `logger.info("capabilities_discovered", ...)` | `await import_adapter_structure(self.adapter, self.graph)` | +1 |
| same function | delete comment `# Add edges for dangerous capabilities` | -1 |
| same function | delete comment `# Run MCP metadata poisoning analysis on discovered capabilities` | -1 |

Net 0; `wc -l scanner.py` stays 750. `run_campaign` and every other function are untouched.
A local (in-function) import was rejected: `ruff format` inserts a blank line after it (+1).

### 7. `ziran/application/factories.py` (edit)

In `load_agent_adapter`, after the `langchain` branch:
```python
    if framework == "langgraph":
        try:
            from ziran.infrastructure.adapters.langgraph_adapter import LangGraphAdapter
        except ImportError as e:
            raise ImportError(
                f"LangGraph not installed. Run: uv sync --extra langchain\n{e}"
            ) from e

        graph = _load_python_object(agent_path, "graph")
        return LangGraphAdapter(graph)
```
Docstring framework list gains ``langgraph`` (agent file must expose a compiled graph as
`graph`).

### 8. CLI and init

- `ziran/interfaces/cli/main.py`: `"langgraph"` appended to the `click.Choice` list of
  `--framework` in `scan` and in `discover` (two one-word edits; `pentest` unchanged, its
  in-process mode is a placeholder).
- `ziran/interfaces/cli/init_command.py`: `_FRAMEWORKS = ["langchain", "langgraph", "crewai",
  "bedrock", "agentcore"]`.

### 9. Docs

- `docs/guides/adapters.md`: new `### LangGraph` section after `### LangChain` with: constructor
  snippet; `Requires: uv sync --extra langchain`; the `ziran discover --framework langgraph
  my_graph.py` and `ziran scan --framework langgraph --agent-path my_graph.py` commands; a line
  `<!-- runnable: langgraph-example -->` immediately followed by one complete ```` ```python ````
  block (the spec's `exfil_graph` shape: scripted planner function, `ToolNode([read_file])`,
  `ToolNode([http_request])`, conditional routing, `graph = builder.compile()`; no model, no
  network); what is mapped (nodes -> agent nodes, edges -> delegation edges with
  `conditional`/`branch_label`, `ToolNode` tools -> capabilities, `ToolNode` messages key ->
  `state:<key>` node); the "possible via shared state" semantics; the limits (tools outside
  `ToolNode`s, no per-key read/write sets for arbitrary nodes, sub-graphs not expanded, routes to
  `END` not represented, `messages` state key required for invoke, `interrupt()` not resumed);
  and a Tips bullet on `discover_structure()` for custom graph-shaped adapters.
- `docs/reference/cli.md`: the two `--framework` rows list `langgraph` too.

### 10. Output shapes (knowledge graph, `export_state()`)

| Entity | id | `node_type` / `edge_type` | attributes |
|---|---|---|---|
| graph node | `langgraph:<name>` | `agent` | `role` (`tool_node`/`subgraph`/`router`/`worker`), `name`, `framework="langgraph"`, `is_entry_point`, `capabilities` (ids) |
| graph edge | `langgraph:<a> -> langgraph:<b>` | `delegates_to` | `delegation_pattern="full_context"`, `conditional`, `branch_label` |
| node uses tool | `langgraph:<name> -> tool_<t>` | `uses_tool` | `timestamp` |
| state channel | `state:<key>` | `agent_state` | `name="state.<key>"`, `channel`, `writers`, `readers`, `description`, `timestamp` |
| tool writes channel | `tool_<t> -> state:<key>` | `accesses_data` | `access="write"` |
| channel feeds tool | `state:<key> -> tool_<t>` | `accesses_data` | `access="read"` |

Resulting chain (unchanged `DangerousChain` shape) in `CampaignResult.dangerous_tool_chains`:
`{"tools": ["tool_read_file", "tool_http_request"], "vulnerability_type":
"data_exfiltration", "chain_type": "indirect", "graph_path": ["tool_read_file",
"state:messages", "tool_http_request"], ...}` plus its composition `VULNERABILITY` node.

| Key | Accepted by | Values |
|---|---|---|
| `--framework langgraph` | `ziran scan`, `ziran discover` | agent file exposing a compiled graph as `graph` |
| `framework: langgraph` | `ziran init` prompt | as above |

## Acceptance criteria -> offline proof

| Criterion (issue, narrowed by the brief) | Proven by | Live model? |
|---|---|---|
| A two-node `StateGraph` sharing a state key produces a cross-node chain finding that the flat LangChain adapter misses on the same agent | `tests/unit/test_langgraph_adapter.py::TestChainFinding` (US2.1 LangGraph -> `data_exfiltration` indirect via `state:messages`; US2.2 `LangChainAdapter` over the same tool objects -> none; US2.3 `run_campaign` -> in `dangerous_tool_chains`) | No |
| Graph nodes/edges are distinct entities in the exported knowledge graph (HTML report / UI) | `tests/unit/application/test_structure_import.py` (US1.4 on `export_state()`, US2.4, skip rules, linear edge count) and `TestChainFinding` (US1.5 via `graph_state_to_vis`, shared `graph_style.json` types) | No; web UI rendering not run (SC-005) |
| Unit tests build a small StateGraph and assert node/edge extraction without an LLM | `tests/unit/test_langgraph_adapter.py::TestDiscoverStructure` / `TestDiscoverCapabilities` / `TestInvoke` (scripted planner node, `pytest.importorskip("langgraph")`) | No |
| Conditional / branching edges represented | `TestDiscoverStructure` (US1.2 `conditional`, `branch_label`) and US1.4 edge attributes | No (route-targeting strategies deferred) |
| Documented in `docs/guides/adapters.md` | `tests/unit/test_langgraph_adapter.py::test_guide_example_runs` (US5.2: extracts the block after `<!-- runnable: langgraph-example -->`, loads it via `load_agent_adapter`, discovers and invokes offline) | No |
| CLI / factory wiring | `tests/unit/application/test_factories.py::TestLoadAgentAdapter::test_langgraph_adapter`; `tests/unit/test_cli_main.py::TestLangGraphFramework` (choices, `ziran discover --framework langgraph` with `CliRunner`) | No |
| Existing adapters untouched | `tests/unit/application/test_structure_import.py` (`MockAgentAdapter` -> hook `None`, graph unchanged) + the unmodified suite | No |
| Size guards | `tests/unit/application/test_scanner_size.py` (unmodified) + `git diff --numstat` | No |
| A real model actually forwards one tool's output into another tool call | not provable offline | **Yes: unverified** (SC-005) |

## Project Structure

### Documentation (this feature)
```text
specs/050-langgraph-native-scanning/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/domain/entities/multi_agent.py                    # edit: AgentEdge fields, StateChannel, state_channels
ziran/domain/interfaces/adapter.py                      # edit: discover_structure() hook (default None)
ziran/infrastructure/adapters/langchain_adapter.py      # edit: extract tool_to_capability (no behaviour change)
ziran/infrastructure/adapters/langgraph_adapter.py      # new: LangGraphAdapter
ziran/application/agent_scanner/structure_import.py     # new: import_adapter_structure, import_structure
ziran/application/agent_scanner/scanner.py              # edit: +2 -2 lines
ziran/application/factories.py                          # edit: langgraph branch
ziran/interfaces/cli/main.py                            # edit: two --framework choices
ziran/interfaces/cli/init_command.py                    # edit: _FRAMEWORKS
docs/guides/adapters.md                                 # edit: LangGraph section
docs/reference/cli.md                                   # edit: framework lists
tests/unit/test_langgraph_adapter.py                    # new
tests/unit/application/test_structure_import.py         # new
tests/unit/test_multi_agent.py                          # extend (domain defaults)
tests/unit/application/test_factories.py                # extend
tests/unit/test_cli_main.py                             # extend
```
**Structure Decision**: domain additions next to the existing topology models; one
infrastructure adapter module; one application sub-module for the graph import so `scanner.py`
gains no lines. `knowledge_graph/graph.py` needs no change: its existing helpers cover every
node and edge.

## Follow-ups (noted, not filed, out of scope)
- Campaign strategies that target a specific conditional route (the edges now carry
  `conditional` / `branch_label`).
- Recursing into sub-graph nodes (`role="subgraph"`) and modelling handoffs between them.
- Per-key read/write sets for non-`ToolNode` nodes from declared `input_schema`s (and tools bound
  in LLM nodes via `bind_tools`), if LangGraph exposes write sets in a later version.
- `find_all_attack_paths` growth through shared channels (bounded by `max_paths`): consider
  de-duplicating paths that differ only after a `state:*` node.
- The `pentest --framework` in-process mode (placeholder today) could reuse the adapter.

## Release note for the implementer
Commit as `feat(adapters): LangGraph state-graph native scanning` (tests may be split as
`test(adapters): ...`, docs as `docs: ...`). No `!`, no `BREAKING CHANGE` (additive port hook
with a default, additive model fields, new CLI choice), no `Co-Authored-By`. PR targets
`develop`, links #393, and reports SC-005 as unverified.

## Phases
- P1 (tests first): domain fields + `StateChannel` + port hook default (FR-001, FR-002).
- P2 (tests first): `structure_import.py` with hand-built topologies; scanner wiring within the
  line budget (FR-004, FR-005, FR-009).
- P3 (tests first): `tool_to_capability` extraction; `LangGraphAdapter` (FR-003).
- P4 (tests first): end-to-end chain finding and contrast; HTML mapper (FR-006).
- P5 (tests first): factory, CLI choices, init (FR-007).
- P6: docs + runnable-example test (FR-008); gates (FR-010).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.
