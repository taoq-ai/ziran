"""Unit tests for the WebSocket protocol handler."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ziran.domain.entities.streaming import AgentResponseChunk
from ziran.infrastructure.adapters.protocols import ProtocolError


def _target_config(url: str = "https://agent.example.com") -> Any:
    config = MagicMock()
    config.normalized_url = url
    config.headers = {}
    return config


# ──────────────────────────────────────────────────────────────────────
# Initialization
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWSInit:
    def test_http_to_ws_conversion(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        assert WebSocketProtocolHandler._http_to_ws("https://example.com") == "wss://example.com"
        assert WebSocketProtocolHandler._http_to_ws("http://example.com") == "ws://example.com"
        assert WebSocketProtocolHandler._http_to_ws("ws://already") == "ws://already"

    def test_default_ws_url(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config("https://agent.io"))
        assert handler._ws_url == "wss://agent.io"

    def test_custom_ws_url(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config(), ws_url="wss://custom/ws")
        assert handler._ws_url == "wss://custom/ws"


# ──────────────────────────────────────────────────────────────────────
# Frame Parsing
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWSFrameParsing:
    def _handler(self) -> Any:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        return WebSocketProtocolHandler(httpx.AsyncClient(), _target_config())

    def test_parse_json_content(self) -> None:
        handler = self._handler()
        chunk = handler._parse_frame(json.dumps({"content": "Hello"}))
        assert chunk.content_delta == "Hello"
        assert chunk.is_final is False

    def test_parse_done_frame(self) -> None:
        handler = self._handler()
        chunk = handler._parse_frame(json.dumps({"content": "bye", "type": "done"}))
        assert chunk.content_delta == "bye"
        assert chunk.is_final is True

    def test_parse_plain_text(self) -> None:
        handler = self._handler()
        chunk = handler._parse_frame("plain text response")
        assert chunk.content_delta == "plain text response"

    def test_parse_bytes_frame(self) -> None:
        handler = self._handler()
        chunk = handler._parse_frame(b"bytes response")
        assert chunk.content_delta == "bytes response"

    def test_parse_tool_call(self) -> None:
        handler = self._handler()
        data = {
            "content": "",
            "tool_call": {"id": "tc1", "name": "search", "arguments": '{"q":"x"}'},
        }
        chunk = handler._parse_frame(json.dumps(data))
        assert chunk.tool_call_delta is not None
        assert chunk.tool_call_delta["name"] == "search"

    def test_parse_dict_content(self) -> None:
        handler = self._handler()
        data = {"content": {"nested": "value"}}
        chunk = handler._parse_frame(json.dumps(data))
        assert "nested" in chunk.content_delta

    def test_parse_numeric_content(self) -> None:
        handler = self._handler()
        data = {"content": 42}
        chunk = handler._parse_frame(json.dumps(data))
        assert chunk.content_delta == "42"

    def test_parse_metadata(self) -> None:
        handler = self._handler()
        data = {"content": "hi", "model": "gpt-4", "usage": {"tokens": 10}}
        chunk = handler._parse_frame(json.dumps(data))
        assert chunk.metadata["model"] == "gpt-4"
        assert chunk.metadata["usage"] == {"tokens": 10}


# ──────────────────────────────────────────────────────────────────────
# Stream send
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWSStreamSend:
    async def test_stream_send_yields_chunks(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        # Mock the WebSocket
        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()

        frames = [
            json.dumps({"content": "Hi"}),
            json.dumps({"content": "", "type": "done"}),
        ]

        async def fake_iter(_self):
            for f in frames:
                yield f

        mock_ws.__aiter__ = fake_iter
        handler._ws = mock_ws

        chunks = []
        async for c in handler.stream_send("test"):
            chunks.append(c)

        assert len(chunks) == 2
        assert chunks[0].content_delta == "Hi"
        assert chunks[1].is_final is True

    async def test_stream_send_handles_exception(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()

        async def fail_iter(_self):
            raise ConnectionError("lost")
            yield  # pragma: no cover

        mock_ws.__aiter__ = fail_iter
        handler._ws = mock_ws

        chunks = []
        async for c in handler.stream_send("test"):
            chunks.append(c)

        assert chunks[-1].is_final is True
        assert "error" in chunks[-1].metadata

    async def test_send_accumulates(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        chunks = [
            AgentResponseChunk(content_delta="A"),
            AgentResponseChunk(content_delta="B"),
            AgentResponseChunk(content_delta="", is_final=True, metadata={"protocol": "websocket"}),
        ]

        async def fake_stream_send(msg, **kw):
            for c in chunks:
                yield c

        handler.stream_send = fake_stream_send  # type: ignore[assignment]
        result = await handler.send("test")
        assert result["content"] == "AB"

    async def test_send_send_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock(side_effect=RuntimeError("fail"))
        handler._ws = mock_ws

        with pytest.raises(ProtocolError, match="send failed"):
            async for _ in handler.stream_send("test"):
                pass


# ──────────────────────────────────────────────────────────────────────
# Health check / discover / close
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWSUtilities:
    async def test_health_check_success(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = MagicMock(spec=httpx.AsyncClient)
        resp = MagicMock()
        resp.status_code = 200
        client.request = AsyncMock(return_value=resp)
        handler = WebSocketProtocolHandler(client, _target_config())

        assert await handler.health_check() is True

    async def test_health_check_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = MagicMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(side_effect=httpx.ConnectError("down"))
        handler = WebSocketProtocolHandler(client, _target_config())

        assert await handler.health_check() is False

    async def test_discover_with_tools(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()
        mock_ws.recv = AsyncMock(
            return_value=json.dumps({"tools": [{"name": "search", "type": "tool"}]})
        )
        handler._ws = mock_ws

        tools = await handler.discover()
        assert len(tools) == 1
        assert tools[0]["name"] == "search"

    async def test_discover_failure_returns_empty(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())
        # No _ws set, _ensure_connected will fail since websockets is mocked
        with patch(
            "ziran.infrastructure.adapters.protocols.ws_handler.WebSocketProtocolHandler._ensure_connected",
            side_effect=RuntimeError("no ws"),
        ):
            tools = await handler.discover()
        assert tools == []

    async def test_close(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        mock_ws = AsyncMock()
        mock_ws.close = AsyncMock()
        handler._ws = mock_ws

        await handler.close()
        assert handler._ws is None

    async def test_close_no_connection(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())
        await handler.close()  # Should not raise

    async def test_ensure_connected_no_websockets(self) -> None:
        from ziran.infrastructure.adapters.protocols.ws_handler import (
            WebSocketProtocolHandler,
        )

        client = httpx.AsyncClient()
        handler = WebSocketProtocolHandler(client, _target_config())

        with (
            patch.dict("sys.modules", {"websockets": None}),
            pytest.raises((ProtocolError, ImportError)),
        ):
            await handler._ensure_connected()
