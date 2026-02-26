"""Amazon Bedrock AgentCore adapter.

Wraps agents built with the ``bedrock-agentcore`` SDK
(``BedrockAgentCoreApp``) to implement the ZIRAN BaseAgentAdapter
interface. Enables in-process security scanning of AgentCore agents
before or after deployment.

Requires the ``agentcore`` extra::

    uv sync --extra agentcore
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.domain.tool_classifier import is_dangerous as _is_dangerous_tool

logger = logging.getLogger(__name__)


class AgentCoreAdapter(BaseAgentAdapter):
    """Adapter for Amazon Bedrock AgentCore agents.

    Wraps a ``BedrockAgentCoreApp`` entrypoint function or any
    callable that accepts a dict payload and returns a dict response.
    This enables scanning AgentCore agents in-process without
    deploying them first.

    Example:
        ```python
        from bedrock_agentcore import BedrockAgentCoreApp
        from ziran.infrastructure.adapters.agentcore_adapter import AgentCoreAdapter

        app = BedrockAgentCoreApp()

        @app.entrypoint
        def invoke(payload):
            return {"result": my_agent(payload["prompt"])}

        adapter = AgentCoreAdapter(invoke)
        response = await adapter.invoke("What can you do?")
        ```
    """

    def __init__(
        self,
        entrypoint: Any,
        *,
        request_field: str = "prompt",
        response_field: str = "result",
        app: Any | None = None,
    ) -> None:
        """Initialize with an AgentCore entrypoint.

        Args:
            entrypoint: The ``@app.entrypoint``-decorated callable, or
                        any function ``f(payload: dict) -> dict``.
            request_field: Key in the payload dict for the user message.
            response_field: Key in the response dict for the agent reply.
            app: Optional ``BedrockAgentCoreApp`` instance for capability
                 discovery and introspection.
        """
        self._entrypoint = entrypoint
        self._request_field = request_field
        self._response_field = response_field
        self._app = app
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the AgentCore agent.

        Constructs a payload dict matching the entrypoint's expected
        format and executes it. Runs in a thread if the entrypoint
        is synchronous.

        Args:
            message: The user prompt.
            **kwargs: Additional fields merged into the payload.

        Returns:
            Standardized agent response.
        """
        payload = {self._request_field: message, **kwargs}

        # Run entrypoint — use thread for sync functions
        if asyncio.iscoroutinefunction(self._entrypoint):
            result = await self._entrypoint(payload)
        else:
            result = await asyncio.to_thread(self._entrypoint, payload)

        # Extract content
        if isinstance(result, dict):
            content = str(result.get(self._response_field, result))
            tool_calls_raw = result.get("tool_calls", [])
        elif isinstance(result, str):
            content = result
            tool_calls_raw = []
        else:
            content = str(result)
            tool_calls_raw = []

        # Parse tool calls
        tool_calls: list[dict[str, Any]] = []
        for tc in tool_calls_raw:
            if isinstance(tc, dict):
                tool_calls.append(
                    {
                        "tool": tc.get("name", tc.get("tool", "unknown")),
                        "input": tc.get("input", tc.get("arguments", {})),
                        "output": tc.get("output", ""),
                    }
                )
                self._observed_tool_calls.append(tool_calls[-1])

        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": content})

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={"protocol": "agentcore"},
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover AgentCore agent capabilities.

        Introspects the ``BedrockAgentCoreApp`` instance for
        registered tools and handlers. Falls back to empty list
        if no app reference is available.

        Returns:
            List of discovered capabilities.
        """
        capabilities: list[AgentCapability] = []

        if self._app is None:
            logger.debug("No BedrockAgentCoreApp instance — skipping capability discovery")
            return capabilities

        # Introspect registered tools from the app
        tools = getattr(self._app, "tools", None) or getattr(self._app, "_tools", None) or {}

        tool_items: Iterable[tuple[Any, Any]]
        if isinstance(tools, dict):
            tool_items = tools.items()
        elif isinstance(tools, list):
            tool_items = ((getattr(t, "name", str(i)), t) for i, t in enumerate(tools))
        else:
            tool_items = ()

        for name, tool in tool_items:
            tool_name = getattr(tool, "name", str(name))
            description = getattr(tool, "description", None)

            # Try to extract parameter schema
            params: dict[str, Any] = {}
            if hasattr(tool, "input_schema"):
                with contextlib.suppress(Exception):
                    params = {"schema": tool.input_schema}

            capabilities.append(
                AgentCapability(
                    id=f"agentcore_tool_{tool_name}",
                    name=tool_name,
                    type=CapabilityType.TOOL,
                    description=description,
                    parameters=params,
                    dangerous=_is_dangerous_tool(tool_name),
                )
            )

        logger.info(
            "Discovered %d AgentCore capabilities (%d dangerous)",
            len(capabilities),
            sum(1 for c in capabilities if c.dangerous),
        )
        return capabilities

    def get_state(self) -> AgentState:
        """Get current agent state snapshot.

        Returns:
            Agent state with conversation history.
        """
        return AgentState(
            session_id=str(id(self._entrypoint)),
            conversation_history=list(self._conversation_history),
            memory={},
        )

    def reset_state(self) -> None:
        """Reset agent to initial state.

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
