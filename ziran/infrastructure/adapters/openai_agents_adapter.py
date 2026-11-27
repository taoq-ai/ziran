"""OpenAI Agents SDK adapter (spec 072).

Wraps an ``agents.Agent`` (the ``openai-agents`` package). Each turn runs ``Runner.run`` and
reports the tools the agent really called. Discovery walks the handoff tree: every agent's
tools become capabilities, and :meth:`discover_structure` reports agents as nodes and
handoffs as edges, which the scanner imports into the knowledge graph.

Requires the ``openai-agents`` extra::

    uv sync --extra openai-agents
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
)
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.domain.tool_classifier import is_dangerous
from ziran.infrastructure.logging.logger import get_logger

try:
    from agents import Agent, Handoff, Runner
    from agents.items import ToolCallItem, ToolCallOutputItem
except ImportError as e:
    raise ImportError(
        "openai-agents is required for OpenAIAgentsAdapter. "
        "Install it with: uv sync --extra openai-agents"
    ) from e

if TYPE_CHECKING:
    from collections.abc import Iterator

    from agents.items import TResponseInputItem

logger = get_logger(__name__)

FRAMEWORK = "openai-agents"
NODE_ID_PREFIX = "openai_agents:"  # AgentNode.id = NODE_ID_PREFIX + agent name

# (target name, target agent or None when unreachable, Handoff object or None for a bare Agent)
_HandoffLink = tuple[str, "Agent[Any] | None", "Handoff[Any, Any] | None"]


def _links(agent: Agent[Any]) -> list[_HandoffLink]:
    links: list[_HandoffLink] = []
    for h in agent.handoffs:
        if isinstance(h, Handoff):
            # shortcut: Handoff exposes its target only via the private _agent_ref weakref;
            # without it the edge stays and the sub-agent's tools are not discovered.
            ref = getattr(h, "_agent_ref", None)
            target = ref() if callable(ref) else None
            links.append((h.agent_name, target if isinstance(target, Agent) else None, h))
        else:
            links.append((h.name, h, None))
    return links


def _walk(entry: Agent[Any]) -> Iterator[tuple[str, Agent[Any] | None, list[_HandoffLink]]]:
    """Breadth-first over the handoff tree, once per agent name (cycle safe)."""
    queue: list[tuple[str, Agent[Any] | None]] = [(entry.name, entry)]
    seen = {entry.name}
    while queue:
        name, agent = queue.pop(0)
        links = _links(agent) if agent is not None else []
        yield name, agent, links
        for target_name, target, _ in links:
            if target_name not in seen:
                seen.add(target_name)
                queue.append((target_name, target))


def _field(raw: Any, key: str) -> Any:
    """Read *key* from a raw SDK item, which is a TypedDict or a pydantic model."""
    return raw.get(key) if isinstance(raw, dict) else getattr(raw, key, None)


def _parse_args(arguments: Any) -> Any:
    if not isinstance(arguments, str):
        return arguments or {}
    try:
        return json.loads(arguments)
    except json.JSONDecodeError:
        return arguments


class OpenAIAgentsAdapter(BaseAgentAdapter):
    """Adapter for OpenAI Agents SDK agents (``agents.Agent``) run in process."""

    def __init__(self, agent: Any) -> None:
        """Wrap *agent*, the entry ``agents.Agent``.

        Raises:
            TypeError: *agent* is not an ``agents.Agent``.
        """
        if not isinstance(agent, Agent):
            raise TypeError(
                f"OpenAIAgentsAdapter expects an agents.Agent, got {type(agent).__name__}"
            )
        self.agent: Agent[Any] = agent
        self._session_id = uuid4().hex
        self._input: list[TResponseInputItem] = []
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Run one turn from the entry agent; earlier turns are kept until ``reset_state()``.

        Extra ``kwargs`` are passed to ``Runner.run`` (for example ``max_turns``).
        """
        user_item: TResponseInputItem = {"role": "user", "content": message}
        result = await Runner.run(self.agent, [*self._input, user_item], **kwargs)
        # Append this turn rather than replace, so concurrent turns do not drop each other.
        self._input += [user_item, *(item.to_input_item() for item in result.new_items)]

        outputs = {
            _field(item.raw_item, "call_id"): str(item.output)
            for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
        }
        tool_calls = []
        for item in result.new_items:
            if isinstance(item, ToolCallItem):
                raw = item.raw_item
                tool_calls.append(
                    {
                        "tool": _field(raw, "name") or _field(raw, "type"),
                        "input": _parse_args(_field(raw, "arguments")),
                        "output": outputs.get(_field(raw, "call_id"), ""),
                    }
                )
        self._observed_tool_calls.extend(tool_calls)

        content = "" if result.final_output is None else str(result.final_output)
        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": content})

        usage = [r.usage for r in result.raw_responses]
        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={"framework": FRAMEWORK, "last_agent": result.last_agent.name},
            prompt_tokens=sum(u.input_tokens for u in usage),
            completion_tokens=sum(u.output_tokens for u in usage),
            total_tokens=sum(u.total_tokens for u in usage),
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Capabilities for the tools of every agent in the handoff tree (deduplicated by id)."""
        capabilities: dict[str, AgentCapability] = {}
        for _, agent, _ in _walk(self.agent):
            for tool in agent.tools if agent is not None else []:
                schema = getattr(tool, "params_json_schema", None)
                capabilities.setdefault(
                    f"tool_{tool.name}",
                    AgentCapability(
                        id=f"tool_{tool.name}",
                        name=tool.name,
                        type=CapabilityType.TOOL,
                        description=getattr(tool, "description", None),
                        parameters={"schema": schema} if schema else {},
                        dangerous=is_dangerous(tool.name),
                    ),
                )

        result = list(capabilities.values())
        logger.info(
            "openai_agents_tools_discovered",
            tool_count=len(result),
            dangerous_count=sum(1 for c in result if c.dangerous),
        )
        return result

    async def discover_structure(self) -> MultiAgentTopology:
        """Agents of the handoff tree as nodes, handoffs as edges, the wrapped agent as entry."""
        agents: list[AgentNode] = []
        edges: list[AgentEdge] = []
        for name, agent, links in _walk(self.agent):
            tools = agent.tools if agent is not None else []
            agents.append(
                AgentNode(
                    id=NODE_ID_PREFIX + name,
                    name=name,
                    role="agent",
                    framework=FRAMEWORK,
                    capabilities=[f"tool_{t.name}" for t in tools],
                    is_entry_point=agent is self.agent,
                )
            )
            edges.extend(
                AgentEdge(
                    source_id=NODE_ID_PREFIX + name,
                    target_id=NODE_ID_PREFIX + target_name,
                    delegation=DelegationPattern.PARTIAL_CONTEXT
                    if h is not None and h.input_filter is not None
                    else DelegationPattern.FULL_CONTEXT,
                )
                for target_name, _, h in links
            )

        return MultiAgentTopology(
            agents=agents,
            edges=edges,
            entry_point_id=NODE_ID_PREFIX + self.agent.name,
            metadata={"framework": FRAMEWORK},
        )

    def get_state(self) -> AgentState:
        """Conversation history of the turns since the last reset."""
        return AgentState(
            session_id=self._session_id,
            conversation_history=list(self._conversation_history),
        )

    @property
    def isolates_sessions(self) -> bool:
        """Each run gets the kept input, and a reset clears it (spec 133)."""
        return True

    def reset_state(self) -> None:
        """Drop the kept conversation and observed calls and start a new session id."""
        self._input = []
        self._conversation_history.clear()
        self._observed_tool_calls.clear()
        self._session_id = uuid4().hex

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        """Record an observed tool call."""
        self._observed_tool_calls.append(
            {"tool": tool_name, "input": inputs, "output": str(outputs)}
        )
