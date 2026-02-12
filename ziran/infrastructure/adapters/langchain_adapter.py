"""LangChain agent adapter.

Wraps LangChain's AgentExecutor to implement the ZIRAN BaseAgentAdapter
interface. Extracts tool calls from intermediate steps and provides
capability discovery from the agent's tool list.

Requires the ``langchain`` extra::

    uv sync --extra langchain
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

if TYPE_CHECKING:
    from langchain.agents import AgentExecutor

logger = logging.getLogger(__name__)

try:
    pass
except ImportError as e:
    raise ImportError(
        "LangChain is required for LangChainAdapter. Install it with: uv sync --extra langchain"
    ) from e


# Tool names that heuristically indicate dangerous capabilities
_DANGEROUS_KEYWORDS: frozenset[str] = frozenset(
    {
        "execute",
        "shell",
        "bash",
        "code",
        "eval",
        "run",
        "file",
        "write",
        "delete",
        "remove",
        "database",
        "sql",
        "query",
        "db",
        "api",
        "web",
        "http",
        "request",
        "fetch",
        "email",
        "send",
        "publish",
        "system",
        "os",
        "subprocess",
        "exec",
    }
)


class LangChainAdapter(BaseAgentAdapter):
    """Adapter for LangChain AgentExecutor agents.

    Bridges between LangChain's agent interface and ZIRAN's standardized
    adapter contract. Provides tool-call observability via intermediate
    steps and capability discovery from the agent's tool list.

    Example:
        ```python
        from langchain.agents import AgentExecutor
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        agent_executor = AgentExecutor(agent=agent, tools=tools)
        adapter = LangChainAdapter(agent_executor)
        response = await adapter.invoke("Hello")
        ```
    """

    def __init__(self, agent: AgentExecutor) -> None:
        """Initialize with a LangChain AgentExecutor.

        Args:
            agent: Configured LangChain AgentExecutor instance.
        """
        self.agent = agent
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the LangChain agent.

        Uses ``ainvoke`` for async execution and extracts tool calls
        from intermediate steps.  Captures token usage via LangChain's
        ``get_openai_callback`` when available.

        Args:
            message: The message/prompt to send.
            **kwargs: Additional parameters passed to ``ainvoke``.

        Returns:
            Standardized agent response.
        """
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0

        # Try to capture token usage via LangChain callback
        cb_ctx = _get_token_callback()
        if cb_ctx is not None:
            with cb_ctx as cb:
                result = await self.agent.ainvoke({"input": message, **kwargs})
                prompt_tokens = cb.prompt_tokens
                completion_tokens = cb.completion_tokens
                total_tokens = cb.total_tokens
        else:
            result = await self.agent.ainvoke({"input": message, **kwargs})

        # Extract tool calls from intermediate_steps
        tool_calls: list[dict[str, Any]] = []
        intermediate_steps = result.get("intermediate_steps", [])
        for action, output in intermediate_steps:
            tool_call = {
                "tool": action.tool,
                "input": action.tool_input,
                "output": str(output),
            }
            tool_calls.append(tool_call)
            self._observed_tool_calls.append(tool_call)

        # Update conversation history
        output_text: str = result["output"]
        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": output_text})

        # Detect LangChain iteration-limit / time-limit sentinel.  When the
        # agent cannot converge the output is a generic error string, but the
        # intermediate_steps still contain every tool call that was attempted.
        # Reporting those tool calls would cause the scanner to treat the
        # response as a successful attack, so we suppress them.
        hit_limit = _is_iteration_limit_response(output_text)
        reported_tool_calls = [] if hit_limit else tool_calls

        return AgentResponse(
            content=output_text,
            tool_calls=reported_tool_calls,
            metadata={
                "intermediate_steps_count": len(intermediate_steps),
                "model": getattr(self.agent, "llm", {}),
                "hit_iteration_limit": hit_limit,
            },
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Extract capabilities from the LangChain agent's tool list.

        Introspects each tool to determine its name, description,
        parameter schema, and potential danger level.

        Returns:
            List of agent capabilities derived from tools.
        """
        capabilities: list[AgentCapability] = []

        tools = getattr(self.agent, "tools", [])
        for tool in tools:
            # Extract parameter schema if available
            params: dict[str, Any] = {}
            if hasattr(tool, "args_schema") and tool.args_schema is not None:
                try:
                    params = {"schema": tool.args_schema.model_json_schema()}
                except Exception:
                    params = {}

            capabilities.append(
                AgentCapability(
                    id=f"tool_{tool.name}",
                    name=tool.name,
                    type=CapabilityType.TOOL,
                    description=getattr(tool, "description", None),
                    parameters=params,
                    dangerous=_is_dangerous_tool(tool.name),
                    requires_permission=getattr(tool, "requires_confirmation", False),
                )
            )

        logger.info(
            "Discovered %d LangChain tools (%d dangerous)",
            len(capabilities),
            sum(1 for c in capabilities if c.dangerous),
        )
        return capabilities

    def get_state(self) -> AgentState:
        """Get current agent state snapshot.

        Returns:
            Agent state with conversation history and memory.
        """
        memory: dict[str, Any] = {}
        if hasattr(self.agent, "memory") and self.agent.memory is not None:
            with contextlib.suppress(Exception):
                memory = {"memory_variables": self.agent.memory.load_memory_variables({})}

        return AgentState(
            session_id=str(id(self.agent)),
            conversation_history=list(self._conversation_history),
            memory=memory,
        )

    def reset_state(self) -> None:
        """Reset agent to initial state.

        Clears conversation history and agent memory.
        """
        self._conversation_history.clear()
        self._observed_tool_calls.clear()
        if hasattr(self.agent, "memory") and self.agent.memory is not None:
            try:
                self.agent.memory.clear()
            except Exception:
                logger.warning("Failed to clear agent memory")

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


def _is_dangerous_tool(tool_name: str) -> bool:
    """Heuristic check for potentially dangerous tools.

    Args:
        tool_name: The tool name to evaluate.

    Returns:
        True if the tool name contains any dangerous keywords.
    """
    name_lower = tool_name.lower()
    return any(keyword in name_lower for keyword in _DANGEROUS_KEYWORDS)


def _get_token_callback() -> Any:
    """Return a LangChain ``get_openai_callback`` async context manager, or *None*.

    This keeps ``langchain_community`` an optional import — if the
    callback helper is unavailable we gracefully skip token tracking.
    """
    try:
        from langchain_community.callbacks.manager import (  # type: ignore[import-not-found,unused-ignore]
            get_openai_callback,
        )

        return get_openai_callback()
    except Exception:
        return None


# Sentinel strings emitted by LangChain's AgentExecutor when the
# iteration or time budget is exceeded.
_ITERATION_LIMIT_SENTINELS: frozenset[str] = frozenset(
    {
        "agent stopped due to iteration limit",
        "agent stopped due to max iterations",
        "agent stopped due to time limit",
    }
)


def _is_iteration_limit_response(text: str) -> bool:
    """Return *True* if *text* is a LangChain iteration/time-limit sentinel."""
    text_lower = text.strip().lower().rstrip(".")
    return any(sentinel in text_lower for sentinel in _ITERATION_LIMIT_SENTINELS)
