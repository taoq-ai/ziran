"""AWS Bedrock agent adapter (stub).

Placeholder adapter for AWS Bedrock Agents. This will be implemented
when the Bedrock Agents SDK stabilizes.

Install with::

    uv sync --extra bedrock  # (not yet available)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

if TYPE_CHECKING:
    from ziran.domain.entities.capability import AgentCapability


class BedrockAdapter(BaseAgentAdapter):
    """Adapter for AWS Bedrock Agents.

    This is a stub implementation. Bedrock Agent support is planned
    for a future release.

    Raises:
        NotImplementedError: All methods raise this until implementation is complete.
    """

    def __init__(self, agent_id: str, **kwargs: Any) -> None:
        """Initialize with a Bedrock agent ID.

        Args:
            agent_id: The AWS Bedrock agent ID.
            **kwargs: Additional AWS configuration (region, credentials, etc.).
        """
        self.agent_id = agent_id
        self.config = kwargs

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the Bedrock agent."""
        raise NotImplementedError(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/ziran"
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover Bedrock agent capabilities."""
        raise NotImplementedError(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/ziran"
        )

    def get_state(self) -> AgentState:
        """Get current agent state."""
        raise NotImplementedError(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/ziran"
        )

    def reset_state(self) -> None:
        """Reset agent state."""
        raise NotImplementedError(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/ziran"
        )

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Observe a tool call."""
        raise NotImplementedError(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/ziran"
        )
