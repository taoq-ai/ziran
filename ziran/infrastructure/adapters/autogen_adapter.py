"""AutoGen AgentChat adapter (spec 073).

Wraps a Microsoft AutoGen AgentChat agent (``autogen_agentchat`` 0.7, for example an
``AssistantAgent``) or a team (``RoundRobinGroupChat``, ``SelectorGroupChat``, ``Swarm``).
Each turn awaits ``run(task=...)`` and reports the tools the agents really called. Discovery
walks nested teams: every agent's tools become capabilities, and :meth:`discover_structure`
reports agents as nodes and the way the team passes turns as edges.

Requires the ``autogen`` extra::

    uv sync --extra autogen
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
    TopologyType,
)
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.domain.tool_classifier import is_dangerous
from ziran.infrastructure.logging.logger import get_logger

try:
    from autogen_agentchat.agents import UserProxyAgent
    from autogen_agentchat.base import ChatAgent, Team
    from autogen_agentchat.messages import (
        BaseChatMessage,
        ToolCallExecutionEvent,
        ToolCallRequestEvent,
    )
    from autogen_agentchat.teams import RoundRobinGroupChat, SelectorGroupChat, Swarm
    from autogen_core import CancellationToken
except ImportError as e:
    raise ImportError(
        "autogen-agentchat is required for AutoGenAdapter. Install it with: uv sync --extra autogen"
    ) from e

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger(__name__)

FRAMEWORK = "autogen"
NODE_ID_PREFIX = "autogen:"  # AgentNode.id = NODE_ID_PREFIX + agent or team name

# shortcut: AgentChat 0.7 exposes team members (_participants), an agent's workbenches
# (_workbench) and its handoffs (_handoffs) only as private attributes; the extra pins <0.8 and
# test_autogen_adapter.TestPrivateApi fails when one goes. Upgrade when a public API appears.


def _members(team: Team) -> list[Any]:
    return list(getattr(team, "_participants", []))


def _agents(target: Any) -> Iterator[Any]:
    """Depth-first over nested teams, yielding the agents."""
    if isinstance(target, Team):
        for member in _members(target):
            yield from _agents(member)
    else:
        yield target


async def _tools(agent: Any) -> list[Any]:
    """The agent's tool schemas (``name``, ``description``, ``parameters``) from its workbenches."""
    schemas: list[Any] = []
    for workbench in getattr(agent, "_workbench", []):
        schemas.extend(await workbench.list_tools())
    return schemas


def _parse_args(arguments: str) -> Any:
    try:
        return json.loads(arguments)
    except json.JSONDecodeError:
        return arguments


class AutoGenAdapter(BaseAgentAdapter):
    """Adapter for AutoGen AgentChat agents and teams run in process."""

    def __init__(self, target: Any) -> None:
        """Wrap *target*, an AgentChat ``ChatAgent`` or ``Team``.

        Raises:
            TypeError: *target* is neither.
        """
        if not isinstance(target, ChatAgent | Team):
            raise TypeError(
                "AutoGenAdapter expects an autogen_agentchat ChatAgent or Team, "
                f"got {type(target).__name__}"
            )
        self.target: Any = target
        self._session_id = uuid4().hex
        self._lock = asyncio.Lock()  # a team refuses a second run while one is going
        self._reset_pending = False
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Run one turn; the agent or team keeps earlier turns until ``reset_state()``.

        Extra ``kwargs`` are passed to ``run`` (for example ``cancellation_token``).
        """
        async with self._lock:
            if self._reset_pending:
                if isinstance(self.target, Team):
                    await self.target.reset()
                else:
                    await self.target.on_reset(CancellationToken())
                self._reset_pending = False
            result = await self.target.run(task=message, output_task_messages=False, **kwargs)

            outputs: dict[str, str] = {}
            calls: list[Any] = []
            for event in result.messages:
                if isinstance(event, ToolCallRequestEvent):
                    calls.extend(event.content)
                elif isinstance(event, ToolCallExecutionEvent):
                    outputs.update({r.call_id: r.content for r in event.content})
            tool_calls = [
                {"tool": c.name, "input": _parse_args(c.arguments), "output": outputs.get(c.id, "")}
                for c in calls
            ]
            self._observed_tool_calls.extend(tool_calls)

            chat = [m for m in result.messages if isinstance(m, BaseChatMessage)]
            content = chat[-1].to_text() if chat else ""
            self._conversation_history.append({"role": "user", "content": message})
            self._conversation_history.append({"role": "assistant", "content": content})

        usage = [m.models_usage for m in result.messages if m.models_usage is not None]
        prompt_tokens = sum(u.prompt_tokens for u in usage)
        completion_tokens = sum(u.completion_tokens for u in usage)
        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={"framework": FRAMEWORK},
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Capabilities for the tools of every agent, nested teams included (deduplicated by id)."""
        capabilities: dict[str, AgentCapability] = {}
        for agent in _agents(self.target):
            for tool in await _tools(agent):
                name = tool["name"]
                schema = tool.get("parameters")
                capabilities.setdefault(
                    f"tool_{name}",
                    AgentCapability(
                        id=f"tool_{name}",
                        name=name,
                        type=CapabilityType.TOOL,
                        description=tool.get("description"),
                        parameters={"schema": schema} if schema else {},
                        dangerous=is_dangerous(name),
                    ),
                )

        result = list(capabilities.values())
        logger.info(
            "autogen_tools_discovered",
            tool_count=len(result),
            dangerous_count=sum(1 for c in result if c.dangerous),
        )
        return result

    async def discover_structure(self) -> MultiAgentTopology:
        """Agents (and selector or nested teams) as nodes, turn passing and handoffs as edges."""
        nodes: dict[str, AgentNode] = {}
        edges: list[AgentEdge] = []
        entry = await self._graph(self.target, nodes, edges, nested=False)
        if entry in nodes:
            nodes[entry].is_entry_point = True

        if isinstance(self.target, SelectorGroupChat):
            topology_type = TopologyType.ROUTER
        elif isinstance(self.target, RoundRobinGroupChat | Swarm):
            topology_type = TopologyType.PEER_TO_PEER
        else:
            topology_type = TopologyType.UNKNOWN
        return MultiAgentTopology(
            topology_type=topology_type,
            agents=list(nodes.values()),
            edges=edges,
            entry_point_id=entry,
            metadata={"framework": FRAMEWORK},
        )

    async def _graph(
        self, target: Any, nodes: dict[str, AgentNode], edges: list[AgentEdge], *, nested: bool
    ) -> str | None:
        """Add *target*'s nodes and edges; return the node id a caller's edge should point to."""
        node_id: str = NODE_ID_PREFIX + target.name
        if not isinstance(target, Team):
            nodes.setdefault(
                node_id,
                AgentNode(
                    id=node_id,
                    name=target.name,
                    role="human" if isinstance(target, UserProxyAgent) else "agent",
                    framework=FRAMEWORK,
                    capabilities=[f"tool_{t['name']}" for t in await _tools(target)],
                ),
            )
            return node_id

        selector = isinstance(target, SelectorGroupChat)
        head = node_id if selector or nested else None
        if head is not None:
            role = "router" if selector else "team"
            nodes.setdefault(
                head, AgentNode(id=head, name=target.name, role=role, framework=FRAMEWORK)
            )

        members = _members(target)
        ids = [await self._graph(m, nodes, edges, nested=True) for m in members]
        member_ids = [i for i in ids if i is not None]

        def edge(source: str, dest: str, **kw: Any) -> AgentEdge:
            # Group chat members all see the whole thread.
            return AgentEdge(
                source_id=source, target_id=dest, delegation=DelegationPattern.FULL_CONTEXT, **kw
            )

        if head is not None:
            edges.extend(edge(head, i, conditional=selector) for i in member_ids)
        if isinstance(target, Swarm):
            for member, source in zip(members, ids, strict=True):
                if source is None:
                    continue
                for handoff in getattr(member, "_handoffs", {}).values():
                    edges.append(
                        edge(
                            source,
                            NODE_ID_PREFIX + handoff.target,
                            conditional=True,
                            branch_label=handoff.name,
                        )
                    )
        elif isinstance(target, RoundRobinGroupChat) and len(member_ids) > 1:
            ring = zip(member_ids, member_ids[1:] + member_ids[:1], strict=True)
            edges.extend(edge(a, b) for a, b in ring)

        return head or (member_ids[0] if member_ids else None)

    def get_state(self) -> AgentState:
        """Conversation history of the turns since the last reset."""
        return AgentState(
            session_id=self._session_id,
            conversation_history=list(self._conversation_history),
        )

    def reset_state(self) -> None:
        """Drop the kept turns and observed calls; the next ``invoke`` awaits AutoGen's reset."""
        self._reset_pending = True
        self._conversation_history.clear()
        self._observed_tool_calls.clear()
        self._session_id = uuid4().hex

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        """Record an observed tool call."""
        self._observed_tool_calls.append(
            {"tool": tool_name, "input": inputs, "output": str(outputs)}
        )
