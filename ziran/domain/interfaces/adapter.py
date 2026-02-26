"""Abstract adapter interface for agent frameworks.

All framework adapters (LangChain, CrewAI, Bedrock, etc.) must implement
BaseAgentAdapter. This ensures the scanner can work with any agent
framework through a consistent contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from ziran.domain.entities.capability import AgentCapability
    from ziran.domain.entities.streaming import AgentResponseChunk


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
    prompt_tokens: int = Field(default=0, ge=0, description="Prompt tokens consumed")
    completion_tokens: int = Field(default=0, ge=0, description="Completion tokens consumed")
    total_tokens: int = Field(default=0, ge=0, description="Total tokens consumed")


class AgentState(BaseModel):
    """Standardized snapshot of agent state.

    Captures conversation history and memory for analysis
    across scan phases.
    """

    session_id: str
    conversation_history: list[dict[str, str]] = Field(default_factory=list)
    memory: dict[str, Any] = Field(default_factory=dict)


class BaseAgentAdapter(ABC):
    """Abstract adapter interface for any agent framework.

    Implementations bridge between the ZIRAN scanner and specific
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

    async def stream(
        self, message: str, **kwargs: Any
    ) -> AsyncIterator[AgentResponseChunk]:
        """Stream a response from the agent chunk by chunk.

        Default implementation falls back to ``invoke()`` and yields
        a single final chunk. Override in adapters that support native
        streaming (SSE, WebSocket, LangChain streaming callbacks, etc.).

        Args:
            message: The message/prompt to send to the agent.
            **kwargs: Additional framework-specific parameters.

        Yields:
            Response chunks with incremental content and metadata.
        """
        from ziran.domain.entities.streaming import AgentResponseChunk

        response = await self.invoke(message, **kwargs)
        yield AgentResponseChunk(
            content_delta=response.content,
            tool_call_delta=None,
            is_final=True,
            metadata={
                "tool_calls": response.tool_calls,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "total_tokens": response.total_tokens,
                **response.metadata,
            },
        )

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
