"""Tests for protocol handlers — REST, OpenAI, MCP, A2A.

All network calls are simulated through httpx.MockTransport so these
tests run fully offline.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from ziran.infrastructure.adapters.protocols import ProtocolError

# ── Fixtures ─────────────────────────────────────────────────────────


def _target_config(url: str = "https://agent.example.com") -> Any:
    """Create a minimal TargetConfig-like object."""
    from ziran.domain.entities.target import TargetConfig

    return TargetConfig(url=url)


def _mock_client(handler_fn) -> httpx.AsyncClient:
    """Build an AsyncClient backed by *handler_fn*."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler_fn))


# ═════════════════════════════════════════════════════════════════════
# REST handler
# ═════════════════════════════════════════════════════════════════════


class TestRestHandler:
    @pytest.fixture()
    def handler(self):
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.content)
                return httpx.Response(200, json={"response": f"echo: {body.get('message', '')}"})
            if request.method in ("HEAD", "OPTIONS"):
                return httpx.Response(200)
            return httpx.Response(404)

        client = _mock_client(_handler)
        return RestProtocolHandler(client, _target_config())

    async def test_send(self, handler) -> None:
        result = await handler.send("hello")
        assert "echo: hello" in result["content"]

    async def test_discover_empty(self, handler) -> None:
        caps = await handler.discover()
        assert caps == []

    async def test_health_check(self, handler) -> None:
        assert await handler.health_check() is True

    async def test_send_http_error(self) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "boom"})

        client = _mock_client(_err)
        h = RestProtocolHandler(client, _target_config())
        with pytest.raises(ProtocolError):
            await h.send("hi")

    async def test_health_check_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client = _mock_client(_err)
        h = RestProtocolHandler(client, _target_config())
        assert await h.health_check() is False


class TestExtractField:
    def test_simple(self) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import _extract_field

        assert _extract_field({"a": "b"}, "a") == "b"

    def test_nested(self) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import _extract_field

        assert _extract_field({"a": {"b": "c"}}, "a.b") == "c"

    def test_missing_returns_fallback(self) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import _extract_field

        result = _extract_field({"x": 1}, "missing")
        assert "1" in result  # falls back to str(data)


# ═════════════════════════════════════════════════════════════════════
# OpenAI handler
# ═════════════════════════════════════════════════════════════════════


class TestOpenAIHandler:
    @pytest.fixture()
    def handler(self):
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            if "/v1/chat/completions" in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {"content": "Hi there!", "role": "assistant"},
                                "finish_reason": "stop",
                            }
                        ],
                        "model": "gpt-4",
                        "usage": {
                            "prompt_tokens": 5,
                            "completion_tokens": 2,
                            "total_tokens": 7,
                        },
                    },
                )
            if "/v1/models" in str(request.url):
                return httpx.Response(
                    200,
                    json={"data": [{"id": "gpt-4", "owned_by": "openai"}]},
                )
            return httpx.Response(404)

        client = _mock_client(_handler)
        return OpenAIProtocolHandler(client, _target_config())

    async def test_send(self, handler) -> None:
        result = await handler.send("hello")
        assert result["content"] == "Hi there!"
        assert result["metadata"]["protocol"] == "openai"
        assert result["metadata"]["total_tokens"] == 7

    async def test_send_maintains_conversation(self, handler) -> None:
        await handler.send("first")
        await handler.send("second")
        assert len(handler._conversation) == 4  # 2 user + 2 assistant

    async def test_discover(self, handler) -> None:
        caps = await handler.discover()
        assert len(caps) == 1
        assert caps[0]["id"] == "gpt-4"

    async def test_health_check(self, handler) -> None:
        assert await handler.health_check() is True

    async def test_reset_conversation(self, handler) -> None:
        await handler.send("hello")
        handler.reset_conversation()
        assert handler._conversation == []

    async def test_send_with_tool_calls(self) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "tc_1",
                                        "function": {
                                            "name": "get_weather",
                                            "arguments": '{"city": "NYC"}',
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "model": "gpt-4",
                    "usage": {},
                },
            )

        client = _mock_client(_handler)
        h = OpenAIProtocolHandler(client, _target_config())
        result = await h.send("weather?")
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["name"] == "get_weather"

    async def test_send_http_error(self) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"error": "rate limited"})

        client = _mock_client(_err)
        h = OpenAIProtocolHandler(client, _target_config())
        with pytest.raises(ProtocolError):
            await h.send("hi")

    async def test_health_check_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        client = _mock_client(_err)
        h = OpenAIProtocolHandler(client, _target_config())
        assert await h.health_check() is False

    async def test_discover_empty_on_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        client = _mock_client(_err)
        h = OpenAIProtocolHandler(client, _target_config())
        assert await h.discover() == []


# ═════════════════════════════════════════════════════════════════════
# MCP handler
# ═════════════════════════════════════════════════════════════════════


class TestMCPHandler:
    @pytest.fixture()
    def handler(self):
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            method = body.get("method", "")

            if method == "completion/complete":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"content": [{"type": "text", "text": "Completed!"}]},
                    },
                )
            if method == "tools/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"tools": [{"name": "search", "description": "Search stuff"}]},
                    },
                )
            if method == "tools/call":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"content": [{"type": "text", "text": "tool result"}]},
                    },
                )
            if method == "resources/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "resources": [
                                {
                                    "uri": "file:///data.txt",
                                    "name": "data",
                                    "description": "A data file",
                                }
                            ]
                        },
                    },
                )
            if method == "prompts/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "prompts": [{"name": "summarize", "description": "Summarize text"}]
                        },
                    },
                )
            if method == "initialize":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"protocolVersion": "2024-11-05"},
                    },
                )
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})

        client = _mock_client(_handler)
        return MCPProtocolHandler(client, _target_config())

    async def test_send(self, handler) -> None:
        result = await handler.send("hello")
        assert result["content"] == "Completed!"
        assert result["metadata"]["protocol"] == "mcp"

    async def test_send_tool_call(self, handler) -> None:
        result = await handler.send("x", tool_name="search", arguments={"q": "test"})
        assert result["content"] == "tool result"

    async def test_discover(self, handler) -> None:
        caps = await handler.discover()
        names = [c["name"] for c in caps]
        assert "search" in names
        assert "data" in names
        assert "summarize" in names

    async def test_health_check(self, handler) -> None:
        assert await handler.health_check() is True

    async def test_health_check_failure(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        client = _mock_client(_err)
        h = MCPProtocolHandler(client, _target_config())
        assert await h.health_check() is False

    async def test_send_fallback_no_completion(self) -> None:
        """When completion/complete and sampling/createMessage both fail."""
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32601, "message": "Method not found"},
                },
            )

        client = _mock_client(_err)
        h = MCPProtocolHandler(client, _target_config())
        result = await h.send("hello")
        assert "does not support direct messaging" in result["content"]

    async def test_jsonrpc_api_error(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        async def _err(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32000, "message": "Server error"},
                },
            )

        client = _mock_client(_err)
        h = MCPProtocolHandler(client, _target_config())
        with pytest.raises(ProtocolError, match="Server error"):
            await h._jsonrpc_call("tools/list", {})

    def test_extract_content_array(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        result = MCPProtocolHandler._extract_content(
            {"content": [{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}]}
        )
        assert result == "hello\nworld"

    def test_extract_content_completion(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        result = MCPProtocolHandler._extract_content({"completion": {"values": [1, 2, 3]}})
        assert result == "1, 2, 3"

    def test_extract_content_empty(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        result = MCPProtocolHandler._extract_content({})
        assert result == ""

    def test_extract_content_fallback_json(self) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        result = MCPProtocolHandler._extract_content({"some": "data"})
        assert "some" in result  # JSON serialized


# ═════════════════════════════════════════════════════════════════════
# A2A handler
# ═════════════════════════════════════════════════════════════════════


class TestA2AHandler:
    def _make_handler(self, transport_fn):
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        client = _mock_client(transport_fn)
        return A2AProtocolHandler(client, _target_config())

    @pytest.fixture()
    def handler(self):
        async def _handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)

            if "/.well-known/agent-card.json" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "TestAgent",
                        "version": "1.0",
                        "url": "https://agent.example.com",
                        "skills": [
                            {
                                "id": "chat",
                                "name": "Chat",
                                "description": "General conversations",
                            }
                        ],
                        "capabilities": {},
                    },
                )
            if "/message:send" in url:
                return httpx.Response(
                    200,
                    json={
                        "task": {
                            "id": "task-1",
                            "contextId": "ctx-1",
                            "status": {"state": "completed"},
                            "artifacts": [
                                {
                                    "artifactId": "a1",
                                    "parts": [{"text": "Hello from A2A!"}],
                                }
                            ],
                        }
                    },
                )
            return httpx.Response(404)

        return self._make_handler(_handler)

    async def test_send(self, handler) -> None:
        result = await handler.send("hello")
        assert result["content"]  # non-empty
        assert result["metadata"]["protocol"] == "a2a"

    async def test_discover(self, handler) -> None:
        caps = await handler.discover()
        assert len(caps) >= 1
        assert caps[0]["name"] == "Chat"

    async def test_health_check(self, handler) -> None:
        assert await handler.health_check() is True

    async def test_health_check_failure(self) -> None:
        async def _err(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        h = self._make_handler(_err)
        assert await h.health_check() is False

    async def test_fetch_agent_card_cached(self, handler) -> None:
        card1 = await handler.fetch_agent_card()
        card2 = await handler.fetch_agent_card()
        assert card1 is card2  # same object = cached

    async def test_fetch_agent_card_force(self, handler) -> None:
        card1 = await handler.fetch_agent_card()
        card2 = await handler.fetch_agent_card(force=True)
        assert card1 is not card2

    async def test_context_management(self, handler) -> None:
        ctx1 = handler.get_context_id()
        assert ctx1
        handler.reset_context()
        ctx2 = handler.get_context_id()
        assert ctx1 != ctx2
        assert handler.get_task_id() is None

    async def test_send_jsonrpc_binding(self) -> None:
        from ziran.domain.entities.target import A2AConfig, TargetConfig
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/.well-known/agent-card.json" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "TestAgent",
                        "version": "1.0",
                        "url": "https://agent.example.com",
                        "skills": [],
                        "capabilities": {},
                    },
                )
            # JSON-RPC response
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body.get("id", 1),
                    "result": {
                        "task": {
                            "id": "task-rpc-1",
                            "contextId": "ctx-rpc-1",
                            "status": {"state": "completed"},
                            "artifacts": [
                                {
                                    "artifactId": "a1",
                                    "parts": [{"text": "RPC answer"}],
                                }
                            ],
                        }
                    },
                },
            )

        cfg = TargetConfig(
            url="https://agent.example.com", a2a=A2AConfig(protocol_binding="JSONRPC")
        )
        client = _mock_client(_handler)
        h = A2AProtocolHandler(client, cfg)
        result = await h.send("hello")
        assert result["metadata"]["protocol"] == "a2a"

    async def test_send_jsonrpc_error(self) -> None:
        from ziran.domain.entities.target import A2AConfig, TargetConfig
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        async def _handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body.get("id", 1),
                    "error": {"code": -32000, "message": "Agent error"},
                },
            )

        cfg = TargetConfig(
            url="https://agent.example.com", a2a=A2AConfig(protocol_binding="JSONRPC")
        )
        client = _mock_client(_handler)
        h = A2AProtocolHandler(client, cfg)
        with pytest.raises(ProtocolError, match="Agent error"):
            await h.send("hello")

    def test_parse_send_response_message_only(self) -> None:
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        resp = A2AProtocolHandler._parse_send_response(
            {"message": {"messageId": "m1", "role": "ROLE_AGENT", "parts": [{"text": "hi"}]}}
        )
        assert resp.message is not None
        assert resp.task is None

    def test_extract_tool_calls_empty(self) -> None:
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        resp = MagicMock()
        resp.task = None
        assert A2AProtocolHandler._extract_tool_calls(resp) == []
