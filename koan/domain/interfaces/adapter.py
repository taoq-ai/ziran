"""Abstract adapter interface for agent frameworks.

All framework adapters (LangChain, CrewAI, Bedrock, etc.) must implement
BaseAgentAdapter. This ensures the scanner can work with any agent
framework through a consistent contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from koan.domain.entities.capability import AgentCapability


class AgentResponse(BaseModel):
    """Standardized response from any agent framework.

    Normalizes the output regardless of whether the underlying
    framework is LangChain, CrewAI, or a custom implementation.
    """

    content: str = Field(description="The agent's text response")
    tool_calls: list[dict[str, Any]] = Field(
        default_factory=list, description="Tools invoked during this response"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Framework-specific metadata"
    )


class AgentState(BaseModel):
    """Standardized snapshot of agent state.

    Captures conversation history and memory for analysis
    across Romance Scan phases.
    """

    session_id: str
    conversation_history: list[dict[str, str]] = Field(default_factory=list)
    memory: dict[str, Any] = Field(default_factory=dict)


class BaseAgentAdapter(ABC):
    """Abstract adapter interface for any agent framework.

    Implementations bridge between the KOAN scanner and specific
    agent frameworks. The adapter handles:
    - Sending messages and receiving responses
    - Discovering agent capabilities (tools, skills, permissions)
    - Observing tool calls for analysis
    - Managing agent state (get/reset)

    Example:
        ```python
        class MyAdapter(BaseAgentAdapter):
            async def invoke(self, message: str, **kwargs) -> AgentResponse:
                result = await my_agent.run(message)
                return AgentResponse(content=result.text)
            ...
        ```
    """

    @abstractmethod
    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the agent and get a response.

        Args:
            message: The message/prompt to send to the agent.
            **kwargs: Additional framework-specific parameters.

        Returns:
            Standardized agent response with content and tool calls.
        """

    @abstractmethod
    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover the agent's tools, skills, and permissions.

        Introspects the agent to find all available capabilities
        that could be part of an attack chain.

        Returns:
            List of discovered capabilities.
        """

    @abstractmethod
    def get_state(self) -> AgentState:
        """Get a snapshot of the current agent state.

        Returns:
            Current agent state including conversation history.
        """

    @abstractmethod
    def reset_state(self) -> None:
        """Reset the agent to its initial state.

        Clears conversation history, memory, and any accumulated
        context. Used between phases or campaigns.
        """

    @abstractmethod
    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call for analysis.

        Called when the agent invokes a tool, allowing the scanner
        to track tool usage patterns for attack chain discovery.

        Args:
            tool_name: Name of the tool that was called.
            inputs: Input parameters passed to the tool.
            outputs: Output returned by the tool.
        """
