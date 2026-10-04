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
are linked; two dangerous tools in the same `ToolNode` are linked too.

**Limits.**

- Only tools inside `ToolNode`s are discovered. Tools bound to a model with `bind_tools`, or
  called from plain function nodes or closures, cannot be introspected.
- No per-key read/write sets for other nodes: LangGraph lists every state key for every node,
  so plain nodes get no state edges.
- Sub-graph nodes are agents with role `subgraph`; they are not expanded.
- Routes to `END` (and the edge from `START`) are not edges; the `START` target is the entry
  point.
- `invoke` sends `{"messages": [...]}`; graphs that pause with `interrupt()` are not resumed.

### CrewAI

```python
from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

adapter = CrewAIAdapter(crew=your_crew)
```

Requires: `uv sync --extra crewai`

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
