"""Unit tests for the SSE protocol handler."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from ziran.domain.entities.streaming import AgentResponseChunk


def _target_config(url: str = "https://api.example.com") -> Any:
    config = MagicMock()
    config.normalized_url = url
    config.headers = {}
    config.rest = None
    return config


class _FakeResponse:
    """Fake httpx.Response for SSE streams."""

    def __init__(self, lines: list[str], status_code: int = 200) -> None:
        self.status_code = status_code
        self._lines = lines
        self._read = False

    async def aiter_bytes(self):
        for line in self._lines:
            yield (line + "\n").encode()

    async def aread(self):
        self._read = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ──────────────────────────────────────────────────────────────────────
# Initialization
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestSSEInit:
    def test_default_openai_mode_url(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        config = _target_config()
        handler = SSEProtocolHandler(client, config)
        assert handler._get_stream_url().endswith("/v1/chat/completions")

    def test_generic_mode_url(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        config = _target_config("https://agent.example.com")
        handler = SSEProtocolHandler(client, config, openai_mode=False)
        assert handler._get_stream_url() == "https://agent.example.com"

    def test_custom_stream_url(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        config = _target_config()
        handler = SSEProtocolHandler(client, config, stream_url="https://custom/stream")
        assert handler._get_stream_url() == "https://custom/stream"

    def test_build_request_body_openai(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        config = _target_config()
        handler = SSEProtocolHandler(client, config, model="gpt-4o")
        body = handler._build_request_body("Hello")
        assert body["model"] == "gpt-4o"
        assert body["stream"] is True
        assert body["messages"][-1]["content"] == "Hello"

    def test_build_request_body_generic(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        config = _target_config()
        handler = SSEProtocolHandler(client, config, openai_mode=False)
        body = handler._build_request_body("ping")
        assert body["message"] == "ping"
        assert body["stream"] is True


# ──────────────────────────────────────────────────────────────────────
# SSE Parsing
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestSSEParsing:
    def test_parse_sse_data_openai_content(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        data_str = json.dumps({"choices": [{"delta": {"content": "hi"}, "finish_reason": None}]})
        chunk = handler._parse_sse_data(data_str, {})
        assert chunk is not None
        assert chunk.content_delta == "hi"

    def test_parse_sse_data_done_sentinel(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        # Non-JSON data gets returned as content_delta
        chunk = handler._parse_sse_data("not json", {})
        assert chunk is not None
        assert chunk.content_delta == "not json"

    def test_parse_sse_data_empty_delta_skipped(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        data_str = json.dumps({"choices": [{"delta": {}, "finish_reason": None}]})
        chunk = handler._parse_sse_data(data_str, {})
        assert chunk is None

    def test_parse_sse_data_tool_call(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        data_str = json.dumps(
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "tc_1",
                                    "function": {"name": "search", "arguments": '{"q":'},
                                }
                            ]
                        },
                        "finish_reason": None,
                    }
                ]
            }
        )
        tc_acc: dict[int, dict[str, Any]] = {}
        chunk = handler._parse_sse_data(data_str, tc_acc)
        assert chunk is not None
        assert chunk.tool_call_delta is not None
        assert tc_acc[0]["name"] == "search"

    def test_parse_sse_data_finish_reason(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        data_str = json.dumps({"choices": [{"delta": {"content": "."}, "finish_reason": "stop"}]})
        chunk = handler._parse_sse_data(data_str, {})
        assert chunk is not None
        assert chunk.metadata.get("finish_reason") == "stop"

    async def test_parse_sse_stream_done(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        lines = [
            'data: {"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}',
            "",
            "data: [DONE]",
        ]
        fake_resp = _FakeResponse(lines)
        chunks = []
        async for c in handler._parse_sse_stream(fake_resp, {}):
            chunks.append(c)
        assert len(chunks) == 2
        assert chunks[0].content_delta == "Hello"
        assert chunks[1].is_final is True

    async def test_parse_sse_stream_no_done(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        lines = [
            'data: {"choices":[{"delta":{"content":"Hi"},"finish_reason":null}]}',
        ]
        fake_resp = _FakeResponse(lines)
        chunks = []
        async for c in handler._parse_sse_stream(fake_resp, {}):
            chunks.append(c)
        # Should still get a final chunk
        assert chunks[-1].is_final is True

    async def test_sse_comment_and_empty_lines_skipped(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = httpx.AsyncClient()
        handler = SSEProtocolHandler(client, _target_config())
        lines = [
            ": this is a comment",
            "",
            'data: {"choices":[{"delta":{"content":"X"},"finish_reason":null}]}',
            "data: [DONE]",
        ]
        fake_resp = _FakeResponse(lines)
        chunks = []
        async for c in handler._parse_sse_stream(fake_resp, {}):
            chunks.append(c)
        assert chunks[0].content_delta == "X"


# ──────────────────────────────────────────────────────────────────────
# Send / health_check / discover
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestSSESend:
    async def test_send_accumulates_content(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = MagicMock(spec=httpx.AsyncClient)
        handler = SSEProtocolHandler(client, _target_config())

        # Mock stream_send to yield chunks
        chunks = [
            AgentResponseChunk(content_delta="Hello "),
            AgentResponseChunk(content_delta="world"),
            AgentResponseChunk(content_delta="", is_final=True, metadata={"protocol": "sse"}),
        ]

        async def fake_stream_send(msg, **kw):
            for c in chunks:
                yield c

        handler.stream_send = fake_stream_send  # type: ignore[assignment]
        result = await handler.send("test")
        assert result["content"] == "Hello world"

    async def test_health_check_success(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = MagicMock(spec=httpx.AsyncClient)
        resp = MagicMock()
        resp.status_code = 200
        client.request = AsyncMock(return_value=resp)
        handler = SSEProtocolHandler(client, _target_config())

        assert await handler.health_check() is True

    async def test_health_check_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = MagicMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(side_effect=httpx.ConnectError("down"))
        handler = SSEProtocolHandler(client, _target_config())

        assert await handler.health_check() is False

    async def test_discover_openai_mode(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = MagicMock(spec=httpx.AsyncClient)
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"data": [{"id": "gpt-4"}]}
        client.get = AsyncMock(return_value=resp)
        handler = SSEProtocolHandler(client, _target_config())

        models = await handler.discover()
        assert len(models) == 1
        assert models[0]["id"] == "gpt-4"

    async def test_discover_non_openai_returns_empty(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import SSEProtocolHandler

        client = MagicMock(spec=httpx.AsyncClient)
        handler = SSEProtocolHandler(client, _target_config(), openai_mode=False)

        models = await handler.discover()
        assert models == []


# ──────────────────────────────────────────────────────────────────────
# _extract_nested helper
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestExtractNested:
    def test_simple_path(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import _extract_nested

        assert _extract_nested({"a": {"b": "c"}}, "a.b") == "c"

    def test_array_index(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import _extract_nested

        data = {"choices": [{"delta": {"content": "hi"}}]}
        assert _extract_nested(data, "choices.0.delta.content") == "hi"

    def test_missing_field(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import _extract_nested

        assert _extract_nested({"a": 1}, "b.c") is None

    def test_invalid_index(self) -> None:
        from ziran.infrastructure.adapters.protocols.sse_handler import _extract_nested

        assert _extract_nested({"a": [1]}, "a.5") is None
