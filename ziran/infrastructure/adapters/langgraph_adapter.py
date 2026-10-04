"""LangGraph adapter (spec 050).

Wraps a compiled LangGraph graph (``StateGraph(...).compile()``). Besides invoking the graph
and discovering the tools of its ``ToolNode``s, it reports the graph's structure (nodes,
edges, conditional routes, shared state channels) through
:meth:`BaseAgentAdapter.discover_structure`, so the scanner can find tool chains that cross
graph nodes through shared state.

Requires the ``langchain`` extra (LangGraph rides with it)::

    uv sync --extra langchain
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
    StateChannel,
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

logger = get_logger(__name__)

FRAMEWORK = "langgraph"
NODE_ID_PREFIX = "langgraph:"  # AgentNode.id = NODE_ID_PREFIX + graph node name
_START, _END = "__start__", "__end__"


class LangGraphAdapter(BaseAgentAdapter):
    """Adapter for compiled LangGraph graphs whose state has a ``messages`` key."""

    def __init__(self, graph: Any) -> None:
        """Wrap *graph*, a compiled LangGraph graph (``StateGraph(...).compile()``).

        Raises:
            TypeError: *graph* is not a compiled graph (a langgraph ``Pregel``).
        """
        if not isinstance(graph, Pregel):
            raise TypeError(
                "LangGraphAdapter expects a compiled graph (a langgraph Pregel); "
                f"call .compile() on the StateGraph builder, got {type(graph).__name__}"
            )
        self.graph = graph
        self._thread_id: str = uuid4().hex
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Run one turn of the graph and report its tool calls, answer and token usage."""
        human = HumanMessage(message, id=uuid4().hex)
        out = await self.graph.ainvoke(
            {"messages": [human], **kwargs},
            config={"configurable": {"thread_id": self._thread_id}},
        )
        msgs: list[Any] = list(out["messages"])
        start = next((i + 1 for i, m in enumerate(msgs) if m.id == human.id), 0)
        turn = msgs[start:]

        outputs = {m.tool_call_id: str(m.content) for m in turn if isinstance(m, ToolMessage)}
        ai_messages = [m for m in turn if isinstance(m, AIMessage)]
        tool_calls = [
            {"tool": tc["name"], "input": tc["args"], "output": outputs.get(tc["id"] or "", "")}
            for m in ai_messages
            for tc in m.tool_calls
        ]
        self._observed_tool_calls.extend(tool_calls)

        content = str(ai_messages[-1].text) if ai_messages else ""
        usage: list[Any] = [m.usage_metadata or {} for m in ai_messages]
        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": content})

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={"framework": FRAMEWORK, "turn_messages": len(turn)},
            prompt_tokens=sum(u.get("input_tokens", 0) for u in usage),
            completion_tokens=sum(u.get("output_tokens", 0) for u in usage),
            total_tokens=sum(u.get("total_tokens", 0) for u in usage),
        )

    def _tool_nodes(self) -> list[tuple[str, Any]]:
        """``(name, ToolNode)`` for every graph node whose runnable is a ``ToolNode``."""
        return [
            (name, node.bound)
            for name, node in self.graph.nodes.items()
            if isinstance(node.bound, ToolNode)
        ]

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Capabilities for the tools of every ``ToolNode`` (deduplicated by id)."""
        capabilities: dict[str, AgentCapability] = {}
        for _, tool_node in self._tool_nodes():
            for tool in tool_node.tools_by_name.values():
                cap = tool_to_capability(tool)
                capabilities.setdefault(cap.id, cap)

        result = list(capabilities.values())
        logger.info(
            "langgraph_tools_discovered",
            tool_count=len(result),
            dangerous_count=sum(1 for c in result if c.dangerous),
        )
        return result

    async def discover_structure(self) -> MultiAgentTopology:
        """The graph's nodes, edges and shared state channels as a topology.

        State channels are coarse: every ``ToolNode`` reads its inputs from and writes its
        results to its messages key, so tools sharing a key may pass data to each other
        ("possible via shared state"). Per-key read/write sets of other nodes are not used.
        """
        all_edges = self.graph.get_graph().edges
        edges = [e for e in all_edges if e.source != _START and e.target != _END]
        entry_names = {e.target for e in all_edges if e.source == _START}
        routers = {e.source for e in edges if e.conditional}
        tool_ids = {
            name: sorted(f"tool_{t}" for t in tool_node.tools_by_name)
            for name, tool_node in self._tool_nodes()
        }

        agents: list[AgentNode] = []
        for name, node in self.graph.nodes.items():
            if name == _START:
                continue
            if name in tool_ids:
                role = "tool_node"
            elif isinstance(node.bound, Pregel):
                role = "subgraph"
            elif name in routers:
                role = "router"
            else:
                role = "worker"
            agents.append(
                AgentNode(
                    id=NODE_ID_PREFIX + name,
                    name=name,
                    role=role,
                    framework=FRAMEWORK,
                    capabilities=tool_ids.get(name, []),
                    is_entry_point=name in entry_names,
                )
            )

        channel_tools: dict[str, set[str]] = {}
        for name, tool_node in self._tool_nodes():
            # ponytail: private attribute behind ToolNode(messages_key=...); "messages" default.
            key = getattr(tool_node, "_messages_key", "messages")
            channel_tools.setdefault(key, set()).update(tool_ids[name])

        return MultiAgentTopology(
            agents=agents,
            edges=[
                AgentEdge(
                    source_id=NODE_ID_PREFIX + e.source,
                    target_id=NODE_ID_PREFIX + e.target,
                    delegation=DelegationPattern.FULL_CONTEXT,
                    conditional=e.conditional,
                    branch_label=None if e.data is None else str(e.data),
                )
                for e in edges
            ],
            state_channels=[
                StateChannel(name=key, writers=sorted(ids), readers=sorted(ids))
                for key, ids in sorted(channel_tools.items())
            ],
            entry_point_id=next((a.id for a in agents if a.is_entry_point), None),
            metadata={"framework": FRAMEWORK},
        )

    def get_state(self) -> AgentState:
        """Conversation history; the session id is the graph's checkpointer thread id."""
        return AgentState(
            session_id=self._thread_id,
            conversation_history=list(self._conversation_history),
        )

    def reset_state(self) -> None:
        """Clear history and observed calls and start a new checkpointer thread."""
        self._conversation_history.clear()
        self._observed_tool_calls.clear()
        self._thread_id = uuid4().hex

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        """Record an observed tool call."""
        self._observed_tool_calls.append(
            {"tool": tool_name, "input": inputs, "output": str(outputs)}
        )
