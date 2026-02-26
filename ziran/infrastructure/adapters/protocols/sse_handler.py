"""Server-Sent Events (SSE) protocol handler for streaming agent responses.

Implements streaming communication with agents that expose SSE endpoints.
SSE is the standard mechanism for OpenAI-compatible streaming (``stream=true``),
custom streaming REST APIs, and many LLM gateway proxies.

The handler sends a POST request and reads the ``text/event-stream`` response
incrementally, yielding ``AgentResponseChunk`` instances as events arrive.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from ziran.domain.entities.streaming import AgentResponseChunk
from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ziran.domain.entities.target import TargetConfig

logger = logging.getLogger(__name__)

# SSE-specific constants
_SSE_CONTENT_TYPE = "text/event-stream"
_DEFAULT_EVENT_DATA_FIELD = "data"
_DONE_SENTINEL = "[DONE]"


class SSEProtocolHandler(BaseProtocolHandler):
    """Handler for agents exposing Server-Sent Events streaming endpoints.

    Supports two modes:
    - **OpenAI-compatible**: Streams from ``/v1/chat/completions`` with
      ``stream=true``, parsing standard OpenAI delta format.
    - **Generic SSE**: Streams from a configurable endpoint, parsing
      ``data:`` lines as JSON with configurable content field paths.

    Usage:
        ```python
        handler = SSEProtocolHandler(client, config)
        async for chunk in handler.stream_send("Hello"):
            print(chunk.content_delta, end="", flush=True)
        ```
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: TargetConfig,
        *,
        stream_url: str | None = None,
        model: str = "gpt-4",
        content_field: str = "choices.0.delta.content",
        finish_field: str = "choices.0.finish_reason",
        openai_mode: bool = True,
    ) -> None:
        """Initialize SSE handler.

        Args:
            client: Shared httpx async client.
            config: Target configuration.
            stream_url: Override URL for the streaming endpoint.
                Defaults to ``{base_url}/v1/chat/completions`` in OpenAI mode,
                or ``{base_url}`` in generic mode.
            model: Model name for OpenAI-compatible requests.
            content_field: Dot-separated path to the content delta in SSE data.
            finish_field: Dot-separated path to the finish reason field.
            openai_mode: If True, format requests as OpenAI chat completions.
        """
        super().__init__(client, config)
        self._stream_url = stream_url
        self._model = model
        self._content_field = content_field
        self._finish_field = finish_field
        self._openai_mode = openai_mode
        self._conversation: list[dict[str, str]] = []

    def _get_stream_url(self) -> str:
        """Resolve the streaming endpoint URL."""
        if self._stream_url:
            return self._stream_url
        base = self._config.normalized_url
        if self._openai_mode:
            return f"{base}/v1/chat/completions"
        return base

    def _build_request_body(self, message: str) -> dict[str, Any]:
        """Build the request body for the streaming request."""
        if self._openai_mode:
            self._conversation.append({"role": "user", "content": message})
            return {
                "model": self._model,
                "messages": list(self._conversation),
                "stream": True,
            }
        # Generic SSE: send message in configurable field
        rest = self._config.rest
        field = rest.message_field if rest else "message"
        body: dict[str, Any] = {field: message, "stream": True}
        if rest and rest.extra_body:
            body.update(rest.extra_body)
        return body

    # ── BaseProtocolHandler Implementation ───────────────────────

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Non-streaming send (accumulates full SSE stream into one response).

        This fallback collects all SSE chunks and returns the full response,
        matching the ``BaseProtocolHandler.send()`` contract.
        """
        full_content: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {"protocol": "sse"}

        async for chunk in self.stream_send(message, **kwargs):
            if chunk.content_delta:
                full_content.append(chunk.content_delta)
            if chunk.tool_call_delta:
                tool_calls.append(chunk.tool_call_delta)
            if chunk.is_final:
                metadata.update(chunk.metadata)

        content = "".join(full_content)
        if self._openai_mode:
            self._conversation.append({"role": "assistant", "content": content})

        return {
            "content": content,
            "tool_calls": tool_calls,
            "metadata": metadata,
        }

    async def stream_send(
        self,
        message: str,
        **kwargs: Any,
    ) -> AsyncIterator[AgentResponseChunk]:
        """Stream a prompt via SSE and yield response chunks.

        Sends a POST request with ``Accept: text/event-stream`` and
        parses the response as a stream of server-sent events.

        Yields:
            ``AgentResponseChunk`` instances as SSE events arrive.

        Raises:
            ProtocolError: On HTTP or SSE parsing errors.
        """
        url = self._get_stream_url()
        body = self._build_request_body(message)

        headers = {"Accept": _SSE_CONTENT_TYPE}

        try:
            async with self._client.stream(
                "POST",
                url,
                json=body,
                headers=headers,
            ) as response:
                if response.status_code >= 400:
                    await response.aread()
                    msg = f"SSE request failed with status {response.status_code}"
                    raise ProtocolError(msg, status_code=response.status_code)

                accumulated_tool_calls: dict[int, dict[str, Any]] = {}
                async for chunk in self._parse_sse_stream(response, accumulated_tool_calls):
                    yield chunk

        except httpx.HTTPError as exc:
            msg = f"SSE stream failed: {exc}"
            raise ProtocolError(msg) from exc

    async def discover(self) -> list[dict[str, Any]]:
        """SSE endpoints typically don't support discovery.

        Falls back to empty list — the adapter uses probe-based discovery.
        """
        if self._openai_mode:
            url = f"{self._config.normalized_url}/v1/models"
            try:
                response = await self._client.get(url)
                response.raise_for_status()
                data = response.json()
                return [
                    {
                        "id": m.get("id", "unknown"),
                        "name": m.get("id", "unknown"),
                        "type": "model",
                    }
                    for m in data.get("data", [])
                ]
            except httpx.HTTPError:
                pass
        return []

    async def health_check(self) -> bool:
        """Check if the SSE endpoint is reachable."""
        try:
            url = self._get_stream_url()
            resp = await self._client.request("OPTIONS", url)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    # ── SSE Parsing ──────────────────────────────────────────────

    async def _parse_sse_stream(
        self,
        response: httpx.Response,
        accumulated_tool_calls: dict[int, dict[str, Any]],
    ) -> AsyncIterator[AgentResponseChunk]:
        """Parse an SSE event stream from an httpx response.

        Handles the standard SSE format::

            data: {"choices":[{"delta":{"content":"Hello"}}]}

            data: [DONE]

        Yields:
            ``AgentResponseChunk`` for each meaningful SSE data event.
        """
        buffer = ""
        async for raw_bytes in response.aiter_bytes():
            text = raw_bytes.decode("utf-8", errors="replace")
            buffer += text

            # Process complete lines
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()

                if not line:
                    continue
                if line.startswith(":"):
                    # SSE comment — skip
                    continue
                if line.startswith(f"{_DEFAULT_EVENT_DATA_FIELD}:"):
                    data_str = line[len(f"{_DEFAULT_EVENT_DATA_FIELD}:") :].strip()

                    if data_str == _DONE_SENTINEL:
                        # Final tool calls
                        final_tools = list(accumulated_tool_calls.values())
                        yield AgentResponseChunk(
                            content_delta="",
                            is_final=True,
                            metadata={
                                "protocol": "sse",
                                "tool_calls": final_tools,
                            },
                        )
                        return

                    chunk = self._parse_sse_data(data_str, accumulated_tool_calls)
                    if chunk is not None:
                        yield chunk

        # Handle case where stream ends without [DONE]
        final_tools = list(accumulated_tool_calls.values())
        yield AgentResponseChunk(
            content_delta="",
            is_final=True,
            metadata={"protocol": "sse", "tool_calls": final_tools},
        )

    def _parse_sse_data(
        self,
        data_str: str,
        accumulated_tool_calls: dict[int, dict[str, Any]],
    ) -> AgentResponseChunk | None:
        """Parse a single SSE data payload into a chunk.

        Args:
            data_str: The raw JSON string from the ``data:`` field.
            accumulated_tool_calls: Mutable dict accumulating tool calls by index.

        Returns:
            An ``AgentResponseChunk`` or None if the payload is empty/skippable.
        """
        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            logger.debug("Non-JSON SSE data: %s", data_str[:100])
            return AgentResponseChunk(content_delta=data_str)

        # Extract content delta
        content = _extract_nested(data, self._content_field) or ""

        # Extract tool call deltas (OpenAI format)
        tool_call_delta = None
        if self._openai_mode:
            choices = data.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                raw_tool_calls = delta.get("tool_calls", [])
                for tc in raw_tool_calls:
                    idx = tc.get("index", 0)
                    if idx not in accumulated_tool_calls:
                        accumulated_tool_calls[idx] = {
                            "id": tc.get("id", ""),
                            "name": tc.get("function", {}).get("name", ""),
                            "arguments": "",
                        }
                    else:
                        # Accumulate arguments
                        args_delta = tc.get("function", {}).get("arguments", "")
                        accumulated_tool_calls[idx]["arguments"] += args_delta
                    tool_call_delta = accumulated_tool_calls[idx]

        # Check finish reason
        finish = _extract_nested(data, self._finish_field)
        is_finished = finish is not None and finish != ""

        if not content and tool_call_delta is None and not is_finished:
            return None

        return AgentResponseChunk(
            content_delta=content,
            tool_call_delta=tool_call_delta,
            is_final=False,  # [DONE] sentinel handles the true final
            metadata={"finish_reason": finish} if finish else {},
        )


def _extract_nested(data: Any, field_path: str) -> Any:
    """Extract a value from nested data using dot-separated path.

    Supports integer indices (e.g., ``choices.0.delta.content``).

    Args:
        data: Parsed JSON data.
        field_path: Dot-separated path.

    Returns:
        Value at the path, or None if not found.
    """
    current = data
    for key in field_path.split("."):
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current
