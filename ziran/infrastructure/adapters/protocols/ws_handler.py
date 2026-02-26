"""WebSocket protocol handler for bidirectional streaming agent communication.

Implements real-time bidirectional communication with agents that expose
WebSocket endpoints. Supports both text and binary frames, JSON-based
message protocols, and persistent connections for multi-turn interactions.

Uses ``websockets`` for async WebSocket communication (optional dependency
under the ``[streaming]`` extra).
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from ziran.domain.entities.streaming import AgentResponseChunk
from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from websockets import ClientConnection

    from ziran.domain.entities.target import TargetConfig

logger = logging.getLogger(__name__)

# Default field paths for JSON-based WebSocket messages
_DEFAULT_MESSAGE_FIELD = "message"
_DEFAULT_CONTENT_FIELD = "content"
_DEFAULT_TYPE_FIELD = "type"
_DEFAULT_DONE_TYPE = "done"


class WebSocketProtocolHandler(BaseProtocolHandler):
    """Handler for agents exposing WebSocket endpoints.

    Supports JSON-based bidirectional messaging with configurable
    field paths for request/response payloads. Maintains a persistent
    connection across multiple interactions.

    The handler sends structured JSON messages and receives streamed
    responses, yielding ``AgentResponseChunk`` instances as frames arrive.

    Usage:
        ```python
        handler = WebSocketProtocolHandler(client, config)
        async for chunk in handler.stream_send("Hello"):
            print(chunk.content_delta, end="", flush=True)
        await handler.close()
        ```
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: TargetConfig,
        *,
        ws_url: str | None = None,
        message_field: str = _DEFAULT_MESSAGE_FIELD,
        content_field: str = _DEFAULT_CONTENT_FIELD,
        type_field: str = _DEFAULT_TYPE_FIELD,
        done_type: str = _DEFAULT_DONE_TYPE,
        extra_connect_kwargs: dict[str, Any] | None = None,
    ) -> None:
        """Initialize WebSocket handler.

        Args:
            client: Shared httpx async client (used only for health checks).
            config: Target configuration.
            ws_url: Override URL for the WebSocket endpoint. If not specified,
                converts the target URL from ``http(s)`` to ``ws(s)``.
            message_field: JSON field name for the outgoing message text.
            content_field: JSON field name for the content in incoming frames.
            type_field: JSON field name that indicates the message type.
            done_type: Value of ``type_field`` that indicates the stream is done.
            extra_connect_kwargs: Additional kwargs passed to ``websockets.connect``.
        """
        super().__init__(client, config)
        self._ws_url = ws_url or self._http_to_ws(config.normalized_url)
        self._message_field = message_field
        self._content_field = content_field
        self._type_field = type_field
        self._done_type = done_type
        self._extra_connect_kwargs = extra_connect_kwargs or {}
        self._ws: ClientConnection | None = None

    @staticmethod
    def _http_to_ws(url: str) -> str:
        """Convert an HTTP(S) URL to a WS(S) URL."""
        if url.startswith("https://"):
            return "wss://" + url[len("https://") :]
        if url.startswith("http://"):
            return "ws://" + url[len("http://") :]
        return url

    async def _ensure_connected(self) -> ClientConnection:
        """Lazily establish the WebSocket connection."""
        if self._ws is not None:
            return self._ws

        try:
            import websockets
        except ImportError as exc:
            msg = (
                "WebSocket support requires the 'websockets' package. "
                "Install it with: pip install ziran[streaming]"
            )
            raise ProtocolError(msg) from exc

        connect_kwargs: dict[str, Any] = {
            **self._extra_connect_kwargs,
        }

        # Forward auth headers from config
        headers = dict(self._config.headers)
        if headers:
            connect_kwargs["additional_headers"] = headers

        try:
            self._ws = await websockets.connect(
                self._ws_url,
                **connect_kwargs,
            )
        except Exception as exc:
            msg = f"WebSocket connection failed: {exc}"
            raise ProtocolError(msg) from exc

        logger.info("WebSocket connected to %s", self._ws_url)
        return self._ws

    # ── BaseProtocolHandler Implementation ───────────────────────

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Non-streaming send (accumulates full WebSocket stream into one response).

        Collects all streamed frames and returns the full response.
        """
        full_content: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {"protocol": "websocket"}

        async for chunk in self.stream_send(message, **kwargs):
            if chunk.content_delta:
                full_content.append(chunk.content_delta)
            if chunk.tool_call_delta:
                tool_calls.append(chunk.tool_call_delta)
            if chunk.is_final:
                metadata.update(chunk.metadata)

        return {
            "content": "".join(full_content),
            "tool_calls": tool_calls,
            "metadata": metadata,
        }

    async def stream_send(  # type: ignore[override]
        self,
        message: str,
        **kwargs: Any,
    ) -> AsyncIterator[AgentResponseChunk]:
        """Send a message via WebSocket and yield streamed response chunks.

        Sends a JSON frame with the message and reads response frames
        until a terminal frame (``done`` type or connection close) is received.

        Yields:
            ``AgentResponseChunk`` instances as WebSocket frames arrive.

        Raises:
            ProtocolError: On WebSocket communication errors.
        """
        ws = await self._ensure_connected()

        # Build outgoing message
        outgoing: dict[str, Any] = {
            self._message_field: message,
        }
        outgoing.update(kwargs)

        try:
            await ws.send(json.dumps(outgoing))
        except Exception as exc:
            msg = f"WebSocket send failed: {exc}"
            raise ProtocolError(msg) from exc

        # Read response frames
        try:
            async for raw_frame in ws:
                chunk = self._parse_frame(raw_frame)
                yield chunk
                if chunk.is_final:
                    return
        except Exception as exc:
            # Connection closed or error — yield final chunk
            yield AgentResponseChunk(
                content_delta="",
                is_final=True,
                metadata={
                    "protocol": "websocket",
                    "error": str(exc),
                },
            )

    async def discover(self) -> list[dict[str, Any]]:
        """WebSocket endpoints don't have a standard discovery mechanism.

        Attempts a ``list_tools`` message if connected, otherwise returns empty.
        """
        try:
            ws = await self._ensure_connected()
            await ws.send(json.dumps({"type": "list_tools"}))

            raw = await ws.recv()
            data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())

            tools = data.get("tools", data.get("capabilities", []))
            return [
                {
                    "id": t.get("id", t.get("name", "unknown")),
                    "name": t.get("name", "unknown"),
                    "type": t.get("type", "tool"),
                    "description": t.get("description", ""),
                }
                for t in tools
                if isinstance(t, dict)
            ]
        except Exception:
            logger.debug("WebSocket discovery not supported")
            return []

    async def health_check(self) -> bool:
        """Check if the WebSocket endpoint is reachable.

        Verifies via HTTP upgrade check (HEAD/OPTIONS on the HTTP URL).
        """
        try:
            # Check HTTP endpoint availability (WebSocket upgrade endpoint)
            http_url = self._config.normalized_url
            resp = await self._client.request("GET", http_url)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None
            logger.debug("WebSocket connection closed")

    # ── Frame Parsing ────────────────────────────────────────────

    def _parse_frame(self, raw: str | bytes) -> AgentResponseChunk:
        """Parse a single WebSocket frame into a chunk.

        Supports:
        - JSON frames with configurable field paths
        - Plain text frames (treated as content deltas)

        Args:
            raw: Raw frame data (text or bytes).

        Returns:
            An ``AgentResponseChunk`` parsed from the frame.
        """
        text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")

        # Try JSON parsing
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Plain text frame — treat as content delta
            return AgentResponseChunk(
                content_delta=text,
                metadata={"protocol": "websocket"},
            )

        # Extract content
        content = data.get(self._content_field, "")
        if isinstance(content, dict):
            content = json.dumps(content)
        elif not isinstance(content, str):
            content = str(content) if content else ""

        # Check if this is the final frame
        msg_type = data.get(self._type_field, "")
        is_final = msg_type == self._done_type

        # Extract tool calls if present
        tool_call_delta = None
        raw_tool_call = data.get("tool_call") or data.get("function_call")
        if raw_tool_call and isinstance(raw_tool_call, dict):
            tool_call_delta = {
                "id": raw_tool_call.get("id", ""),
                "name": raw_tool_call.get("name", ""),
                "arguments": raw_tool_call.get("arguments", ""),
            }

        # Collect metadata
        metadata: dict[str, Any] = {"protocol": "websocket"}
        if "model" in data:
            metadata["model"] = data["model"]
        if "usage" in data:
            metadata["usage"] = data["usage"]

        return AgentResponseChunk(
            content_delta=content,
            tool_call_delta=tool_call_delta,
            is_final=is_final,
            metadata=metadata,
        )
