"""Protocol handler abstraction for remote agent communication.

Defines the interface that all protocol-specific handlers must implement,
providing a consistent API for the HttpAgentAdapter to interact with
agents over different wire protocols.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import httpx

    from ziran.domain.entities.streaming import AgentResponseChunk
    from ziran.domain.entities.target import TargetConfig


class ProtocolResponse(TypedDict):
    """Structured response from a protocol handler's ``send`` method."""

    content: str
    tool_calls: NotRequired[list[dict[str, Any]]]
    metadata: NotRequired[dict[str, Any]]
    prompt_tokens: NotRequired[int]
    completion_tokens: NotRequired[int]
    total_tokens: NotRequired[int]
    model: NotRequired[str]


class ProtocolError(Exception):
    """Raised when a protocol-level error occurs."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.headers = headers


class BaseProtocolHandler(ABC):
    """Abstract base for protocol-specific communication handlers.

    Each implementation translates between Ziran's generic
    ``send``/``discover`` interface and a specific wire protocol
    (REST, OpenAI, MCP, A2A).

    Handlers are instantiated by ``HttpAgentAdapter`` with a shared
    ``httpx.AsyncClient`` and the scan target configuration.
    """

    def __init__(self, client: httpx.AsyncClient, config: TargetConfig) -> None:
        self._client = client
        self._config = config

    @abstractmethod
    async def send(self, message: str, **kwargs: Any) -> ProtocolResponse:
        """Send a prompt to the remote agent and return the raw response.

        Args:
            message: The text prompt to send.
            **kwargs: Protocol-specific options.

        Returns:
            A ``ProtocolResponse`` containing at minimum:
            - ``content`` (str): The agent's text response.
            Optionally:
            - ``tool_calls``: Any tool invocations observed.
            - ``metadata``: Protocol-specific metadata.
            - ``prompt_tokens``, ``completion_tokens``, ``total_tokens``: Usage.
            - ``model``: Model identifier.

        Raises:
            ProtocolError: On transport or protocol-level failures.
        """

    @abstractmethod
    async def discover(self) -> list[dict[str, Any]]:
        """Discover the agent's capabilities via protocol-specific means.

        Returns:
            List of raw capability descriptors. Each dict should contain
            at least ``id``, ``name``, and ``type`` keys. The
            ``HttpAgentAdapter`` maps these to ``AgentCapability`` objects.

        Raises:
            ProtocolError: If discovery fails.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify that the remote agent endpoint is reachable.

        Returns:
            True if the endpoint responds successfully.
        """

    async def close(self) -> None:  # noqa: B027
        """Clean up any protocol-specific resources.

        Called when the adapter is torn down. Override if the handler
        holds additional state beyond the shared ``httpx.AsyncClient``.
        """

    async def stream_send(
        self,
        message: str,
        **kwargs: Any,
    ) -> AsyncIterator[AgentResponseChunk]:
        """Stream a prompt to the remote agent and yield response chunks.

        Default implementation falls back to ``send()`` and yields a
        single final chunk — override in streaming-capable handlers
        (SSE, WebSocket, OpenAI streaming).

        Args:
            message: The text prompt to send.
            **kwargs: Protocol-specific options.

        Yields:
            ``AgentResponseChunk`` instances as they arrive.

        Raises:
            ProtocolError: On transport or protocol-level failures.
        """
        from ziran.domain.entities.streaming import AgentResponseChunk

        result = await self.send(message, **kwargs)
        yield AgentResponseChunk(
            content_delta=result.get("content", ""),
            tool_call_delta=None,
            is_final=True,
            metadata=result.get("metadata", {}),
        )
