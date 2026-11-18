# Framework Adapters

ZIRAN uses adapters to communicate with different agent frameworks. This guide explains how to use built-in adapters and create custom ones.

## Built-in Adapters

### LangChain

```python
from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent_executor=your_agent_executor)
```

Requires: `uv sync --extra langchain`

### LangGraph

```python
from ziran.infrastructure.adapters.langgraph_adapter import LangGraphAdapter

adapter = LangGraphAdapter(graph=builder.compile())  # a compiled StateGraph
```

Requires: `uv sync --extra langchain` (LangGraph is installed with it).

The agent file must expose the compiled graph as `graph`:

```bash
ziran discover --framework langgraph my_graph.py
ziran scan --framework langgraph --agent-path my_graph.py
```

A complete, offline example (a scripted planner stands in for the model, so it runs without
an LLM or network):

<!-- runnable: langgraph-example -->
```python
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode


@tool
def read_file(path: str) -> str:
    """Read a local file."""
    return "internal notes"


@tool
def http_request(url: str) -> str:
    """Send an HTTP request."""
    return "sent"


def planner(state: MessagesState) -> dict:
    """Read a file, send it somewhere, then answer (a real graph calls a model here)."""
    msgs = state["messages"]
    last_human = max(i for i, m in enumerate(msgs) if isinstance(m, HumanMessage))
    done = sum(isinstance(m, ToolMessage) for m in msgs[last_human:])
    if done == 0:
        call = {"name": "read_file", "args": {"path": "notes.txt"}, "id": uuid4().hex}
    elif done == 1:
        call = {"name": "http_request", "args": {"url": "https://example.invalid"}, "id": uuid4().hex}
    else:
        return {"messages": [AIMessage("done")]}
    return {"messages": [AIMessage("", tool_calls=[call])]}


def route(state: MessagesState) -> str:
    calls = getattr(state["messages"][-1], "tool_calls", None)
    if not calls:
        return "end"
    return "read" if calls[-1]["name"] == "read_file" else "send"


builder = StateGraph(MessagesState)
builder.add_node("planner", planner)
builder.add_node("reader", ToolNode([read_file]))
builder.add_node("sender", ToolNode([http_request]))
builder.add_edge(START, "planner")
builder.add_conditional_edges("planner", route, {"read": "reader", "send": "sender", "end": END})
builder.add_edge("reader", "planner")
builder.add_edge("sender", "planner")
graph = builder.compile()
```

**What is mapped.** Besides invoking the graph (tool calls, answer and token usage are read
from the turn's messages; the state must have a `messages` key), the adapter reports the
graph's structure, which the scanner imports into the knowledge graph:

| Graph | Knowledge graph |
|---|---|
| node `reader` | agent node `langgraph:reader` (role `tool_node`, `router`, `subgraph` or `worker`) |
| edge `planner -> reader` | `delegates_to` edge with `conditional` and `branch_label` (`"read"`) |
| tools of a `ToolNode` | capabilities `tool_<name>`, linked to their node with `uses_tool` |
| a `ToolNode`'s messages key | node `state:messages` with `tool -> state` and `state -> tool` `accesses_data` edges |

In the example, `read_file` (node `reader`) and `http_request` (node `sender`) never share a
node, yet the tool-chain analysis reports an indirect `data_exfiltration` chain
`tool_read_file -> state:messages -> tool_http_request`. The flat LangChain adapter, which sees
only a list of tools, does not.

**"Possible via shared state".** A state-channel chain means one tool's output *can* reach the
other tool through shared state, not that it was observed. Every `ToolNode` reads its tool
calls from and writes its results to its messages key, so all `ToolNode` tools on the same key
are linked; two dangerous tools in the same `ToolNode` are linked too. So even a plain
`create_agent` graph with `read_file` and `http_request` gets a critical `data_exfiltration`
chain and can get a VULNERABLE verdict, while `LangChainAdapter` with the same tools reports
neither.

**Limits.**

- Only tools inside `ToolNode`s are discovered. Tools bound to a model with `bind_tools`, or
  called from plain function nodes or closures, cannot be introspected.
- No per-key read/write sets for other nodes: LangGraph lists every state key for every node,
  so plain nodes get no state edges.
- Sub-graph nodes are agents with role `subgraph`; they are not expanded.
- Routes to `END` (and the edge from `START`) are not edges; the `START` target is the entry
  point.
- `invoke` sends `{"messages": [...]}`; graphs that pause with `interrupt()` are not resumed.
- With a checkpointer, all attacks of one phase share a thread (it is reset per phase), so
  later attacks see earlier attacks' history. Each attack's tool calls are still attributed
  to it.

### CrewAI

```python
from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

adapter = CrewAIAdapter(crew=your_crew)
```

Requires: `uv sync --extra crewai`

### OpenAI Agents SDK

```python
from ziran.infrastructure.adapters.openai_agents_adapter import OpenAIAgentsAdapter

adapter = OpenAIAgentsAdapter(agent=your_agent)  # an agents.Agent
```

Requires: `uv sync --extra openai-agents` (or `pip install ziran[openai-agents]`).

The agent file must expose the entry `agents.Agent` as `agent`:

```bash
ziran discover --framework openai-agents agent.py
ziran scan --framework openai-agents --agent-path agent.py
```

See [`examples/26-openai-agents-scan/`](https://github.com/taoq-ai/ziran/tree/main/examples/26-openai-agents-scan)
for a support agent with a billing handoff.

**What is mapped.** Each turn runs `Runner.run` from the entry agent, with the conversation of
earlier turns until the scanner resets state. Tool calls and their outputs come from the run's
items, the answer from `final_output`, token counts from the model responses. Discovery walks
the handoff tree:

| Agents SDK | Knowledge graph |
|---|---|
| agent `billing` | agent node `openai_agents:billing` (the wrapped agent is the entry point) |
| handoff `support -> billing` | `delegates_to` edge, `partial_context` when the handoff has an `input_filter`, else `full_context` |
| tools of an agent | capabilities `tool_<name>` with description and JSON schema, linked with `uses_tool` |

**Limits.** Tools from `mcp_servers`, guardrails, realtime and voice agents are not read.
Streaming falls back to one `invoke`. Agents are identified by name. The SDK's own tracing
stays as you configured it, so with tracing on, attack prompts appear in your traces. To
turn it off, set `OPENAI_AGENTS_DISABLE_TRACING=1` or call
`agents.set_tracing_disabled(True)` in the agent file.

### AutoGen AgentChat

```python
from ziran.infrastructure.adapters.autogen_adapter import AutoGenAdapter

adapter = AutoGenAdapter(your_team)  # an AgentChat team, or an agent such as AssistantAgent
```

Requires: `uv sync --extra autogen` (or `pip install ziran[autogen]`). The adapter targets
Microsoft's `autogen-agentchat` 0.7, not AG2's classic `GroupChat` API.

The agent file must expose the team as `team`, or a single agent as `agent`:

```bash
ziran discover --framework autogen agent.py
ziran scan --framework autogen --agent-path agent.py
```

See [`examples/27-autogen-agent/`](https://github.com/taoq-ai/ziran/tree/main/examples/27-autogen-agent)
for a code-writer team of a coder and a reviewer.

**What is mapped.** Each turn awaits `run(task=...)`; the agent or team keeps earlier turns
until the scanner resets state. Tool calls and their results come from the tool-call request
and execution events, the answer from the last chat message, token counts from
`models_usage`. Discovery walks nested teams:

| AgentChat | Knowledge graph |
|---|---|
| agent `coder` | agent node `autogen:coder` (role `human` for a `UserProxyAgent`) |
| `RoundRobinGroupChat` | a ring of `delegates_to` edges between members, in speaking order |
| `SelectorGroupChat` named `desk` | router node `autogen:desk` with conditional edges to each member |
| `Swarm` handoff `transfer_to_billing` | conditional `delegates_to` edge labelled with the handoff name |
| team nested in a team | team node with edges to its members |
| tools of an agent | capabilities `tool_<name>` with description and JSON schema, linked with `uses_tool` |

**Limits.** Team members, tools and handoffs are read from private AgentChat attributes, so the
extra pins `autogen-agentchat<0.8`. A team without a termination condition runs until AutoGen
stops it, so give the team one (`MaxMessageTermination` for example). Turns run one at a time.
A `UserProxyAgent` reads `input()` by default, so `ziran scan` waits on stdin each time it
speaks; give it an `input_func` for unattended scans.
Streaming falls back to one `invoke`. Tools are listed through each agent's workbenches, so an
MCP workbench starts its server during discovery. MagenticOne, GraphFlow edges, agents inside a
`SocietyOfMindAgent` and agents wrapped as tools are not read.

## Creating a Custom Adapter

Implement the `BaseAgentAdapter` abstract class:

```python
from ziran.domain.interfaces.adapter import BaseAgentAdapter, AgentResponse, AgentState
from ziran.domain.entities.capability import AgentCapability, CapabilityType

class MyAdapter(BaseAgentAdapter):
    def __init__(self, my_agent):
        self.agent = my_agent

    async def invoke(self, message: str, **kwargs) -> AgentResponse:
        """Send a message and get a response."""
        result = await self.agent.run(message)
        return AgentResponse(
            content=result.text,
            tool_calls=result.get_tool_calls(),
            metadata={"framework": "my_framework"},
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """List the agent's tools and capabilities."""
        tools = self.agent.get_tools()
        return [
            AgentCapability(
                id=f"tool_{t.name}",
                name=t.name,
                type=CapabilityType.TOOL,
                description=t.description,
                dangerous=t.name in ["shell_execute", "eval"],
            )
            for t in tools
        ]

    def get_state(self) -> AgentState:
        """Get current conversation state."""
        return AgentState(
            session_id="my-session",
            conversation_history=self.agent.get_history(),
        )

    def reset_state(self) -> None:
        """Reset conversation state."""
        self.agent.clear_history()
```

### Tips

- Mark dangerous tools in `discover_capabilities()` — this improves knowledge graph analysis
- Include `tool_calls` in `AgentResponse` when possible — ZIRAN uses this for detection
- Implement `observe_tool_call()` if your framework supports tool call hooks
- For graph-shaped frameworks, override `discover_structure()` to return a
  `MultiAgentTopology` (nodes, edges, `state_channels`); the scanner imports it next to the
  capabilities. The default returns `None`.
