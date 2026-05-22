"""Native Anthropic SDK adapter.

Wraps ``anthropic.Anthropic`` or ``anthropic.AsyncAnthropic`` to
implement the ZIRAN BaseAgentAdapter interface, enabling direct
security scanning of Claude-based agents without LangChain.

Requires the ``anthropic`` extra::

    uv sync --extra anthropic
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING, Any

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ziran.domain.entities.streaming import AgentResponseChunk

logger = logging.getLogger(__name__)


class AnthropicAdapter(BaseAgentAdapter):
    """Adapter for agents built with the Anthropic Python SDK.

    Wraps an ``anthropic.Anthropic`` (sync) or
    ``anthropic.AsyncAnthropic`` (async) client to implement the
    ZIRAN scanning interface.

    Example::

        import anthropic
        from ziran.infrastructure.adapters.anthropic_adapter import (
            AnthropicAdapter,
        )

        client = anthropic.Anthropic()
        adapter = AnthropicAdapter(
            client=client,
            model="claude-sonnet-4-20250514",
            tools=[{
                "name": "get_weather",
                "description": "Get weather for a location",
                "input_schema": {"type": "object", "properties": {...}},
            }],
        )
        response = await adapter.invoke("What's the weather in London?")
    """

    def __init__(
        self,
        client: Any,
        *,
        model: str = "claude-sonnet-4-20250514",
        system_prompt: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
    ) -> None:
        """Initialize the Anthropic adapter.

        Args:
            client: An ``anthropic.Anthropic`` or
                ``anthropic.AsyncAnthropic`` instance.
            model: Model identifier (e.g. ``claude-sonnet-4-20250514``).
            system_prompt: Optional system prompt prepended to every
                request.
            tools: List of Anthropic tool definitions (dicts with
                ``name``, ``description``, ``input_schema``).
            max_tokens: Maximum tokens for the response.
        """
        self._client = client
        self._model = model
        self._system_prompt = system_prompt
        self._tools = tools or []
        self._max_tokens = max_tokens
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

        # Detect if client is async or sync.
        self._is_async = hasattr(client, "messages") and asyncio.iscoroutinefunction(
            getattr(client.messages, "create", None)
        )

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to Claude and return the response."""
        self._conversation_history.append({"role": "user", "content": message})

        # Build request kwargs.
        req_kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": m["role"], "content": m["content"]} for m in self._conversation_history
            ],
        }
        if self._system_prompt:
            req_kwargs["system"] = self._system_prompt
        if self._tools:
            req_kwargs["tools"] = self._tools

        # Call the API (async or sync via thread).
        if self._is_async:
            response = await self._client.messages.create(**req_kwargs)
        else:
            response = await asyncio.to_thread(self._client.messages.create, **req_kwargs)

        # Extract text and tool calls from content blocks.
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    {
                        "tool_name": block.name,
                        "tool_input": block.input,
                        "tool_call_id": block.id,
                    }
                )

        content = "\n".join(text_parts)
        self._conversation_history.append({"role": "assistant", "content": content})

        # Extract token usage.
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "output_tokens", 0) if usage else 0

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={
                "model": response.model,
                "stop_reason": response.stop_reason,
            },
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover capabilities from the tool definitions."""
        capabilities: list[AgentCapability] = []
        for tool in self._tools:
            name = tool.get("name", "unknown")
            description = tool.get("description", "")
            capabilities.append(
                AgentCapability(
                    id=f"anthropic_tool_{name}",
                    name=name,
                    type=CapabilityType.TOOL,
                    description=description,
                    parameters=tool.get("input_schema", {}),
                )
            )
        return capabilities

    def get_state(self) -> AgentState:
        """Return current conversation state."""
        return AgentState(
            session_id=str(uuid.uuid4()),
            conversation_history=list(self._conversation_history),
            memory={"observed_tool_calls": list(self._observed_tool_calls)},
        )

    def reset_state(self) -> None:
        """Clear conversation history and observed tool calls."""
        self._conversation_history.clear()
        self._observed_tool_calls.clear()

    async def stream(self, message: str, **kwargs: Any) -> AsyncIterator[AgentResponseChunk]:
        """Stream a response from Claude.

        Falls back to the base class single-chunk implementation.
        Override if native streaming is needed.
        """
        async for chunk in super().stream(message, **kwargs):
            yield chunk

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call."""
        self._observed_tool_calls.append(
            {
                "tool_name": tool_name,
                "inputs": inputs,
                "outputs": outputs,
            }
        )
