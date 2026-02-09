"""CrewAI agent adapter.

Wraps CrewAI's Crew to implement the KOAN BaseAgentAdapter interface.
Since CrewAI uses synchronous execution, this adapter uses
``asyncio.to_thread`` to maintain a clean async contract.

Requires the ``crewai`` extra::

    uv sync --extra crewai
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from koan.domain.entities.capability import AgentCapability, CapabilityType
from koan.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

if TYPE_CHECKING:
    from crewai import Crew

logger = logging.getLogger(__name__)

try:
    pass
except ImportError as e:
    raise ImportError(
        "CrewAI is required for CrewAIAdapter. Install it with: uv sync --extra crewai"
    ) from e


class CrewAIAdapter(BaseAgentAdapter):
    """Adapter for CrewAI crews.

    Bridges between CrewAI's synchronous crew interface and KOAN's
    async adapter contract. Uses ``asyncio.to_thread`` to run the
    synchronous ``kickoff()`` without blocking the event loop.

    Example:
        ```python
        from crewai import Crew
        from koan.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        crew = Crew(agents=[...], tasks=[...])
        adapter = CrewAIAdapter(crew)
        response = await adapter.invoke("Analyze security posture")
        ```
    """

    def __init__(self, crew: Crew) -> None:
        """Initialize with a CrewAI Crew.

        Args:
            crew: Configured CrewAI Crew instance.
        """
        self.crew = crew
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Invoke the CrewAI crew.

        Runs the synchronous ``kickoff()`` in a thread pool to maintain
        the async contract without blocking.

        Args:
            message: The message/task description to send.
            **kwargs: Additional parameters passed to ``kickoff``.

        Returns:
            Standardized agent response.
        """
        inputs = {"message": message, **kwargs}

        # Run synchronous CrewAI kickoff in a thread to keep async contract clean
        result = await asyncio.to_thread(self.crew.kickoff, inputs=inputs)

        content = str(result)

        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": content})

        return AgentResponse(
            content=content,
            tool_calls=[],  # CrewAI doesn't expose intermediate tool calls easily
            metadata={
                "crew_size": len(self.crew.agents),
                "task_count": len(self.crew.tasks),
            },
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover capabilities from all agents in the crew.

        Extracts tools from each agent and also records agent roles
        and goals as skill-type capabilities.

        Returns:
            List of capabilities across all crew agents.
        """
        capabilities: list[AgentCapability] = []

        for idx, agent in enumerate(self.crew.agents):
            # Extract tools from each agent
            agent_tools = getattr(agent, "tools", []) or []
            for tool in agent_tools:
                tool_name = getattr(tool, "name", str(tool))
                capabilities.append(
                    AgentCapability(
                        id=f"agent_{idx}_tool_{tool_name}",
                        name=tool_name,
                        type=CapabilityType.TOOL,
                        description=getattr(tool, "description", None),
                        parameters={},
                        dangerous=False,
                    )
                )

            # Agent roles and goals are skill-type capabilities
            role = getattr(agent, "role", f"Agent {idx}")
            goal = getattr(agent, "goal", "")
            capabilities.append(
                AgentCapability(
                    id=f"agent_{idx}_role",
                    name=f"Agent Role: {role}",
                    type=CapabilityType.SKILL,
                    description=goal,
                    parameters={},
                    dangerous=False,
                )
            )

        logger.info(
            "Discovered %d capabilities across %d CrewAI agents",
            len(capabilities),
            len(self.crew.agents),
        )
        return capabilities

    def get_state(self) -> AgentState:
        """Get current crew state snapshot.

        Returns:
            Agent state with conversation history.
        """
        return AgentState(
            session_id=str(id(self.crew)),
            conversation_history=list(self._conversation_history),
            memory={},
        )

    def reset_state(self) -> None:
        """Reset crew to initial state.

        Clears conversation history and observed tool calls.
        """
        self._conversation_history.clear()
        self._observed_tool_calls.clear()

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call.

        Args:
            tool_name: Name of the tool invoked.
            inputs: Input parameters.
            outputs: Tool output.
        """
        self._observed_tool_calls.append(
            {
                "tool": tool_name,
                "input": inputs,
                "output": str(outputs),
            }
        )
