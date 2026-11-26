"""MCP version negotiation, the 2026-07-28 request shape and input_required (spec 110)."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from tests.mcp_servers import MODERN, LegacyServer, ModernServer
from ziran.domain.entities.target import ProtocolType, TargetConfig
from ziran.infrastructure.adapters.protocols import ProtocolError
from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

pytestmark = pytest.mark.unit

URL = "https://mcp.example.com/rpc"
_META = "io.modelcontextprotocol/protocolVersion"


def _handler(server: ModernServer | LegacyServer, url: str = URL) -> MCPProtocolHandler:
    return MCPProtocolHandler(
        httpx.AsyncClient(transport=server.transport()), TargetConfig(url=url)
    )


class TestModernServer:
    async def test_discovery_and_calls_carry_the_2026_shape(self) -> None:
        server = ModernServer()
        handler = _handler(server)
        assert [c["name"] for c in await handler.discover()] == ["search", "login"]
        reply = await handler.send("hello")
        tool = await handler.send("x", tool_name="search", arguments={"q": "a"})
        assert reply["content"] == "modern reply: hello"
        assert tool["content"] == "modern tool search"
        methods = [b["method"] for b in server.bodies]
        assert methods[0] == "server/discover" and "initialize" not in methods
        for request, body in zip(server.requests, server.bodies, strict=True):
            meta = body["params"]["_meta"]
            assert meta[_META] == MODERN
            assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "ziran-scanner"
            assert meta["io.modelcontextprotocol/clientCapabilities"] == {
                "elicitation": {"form": {}, "url": {}}
            }
            assert request.headers["mcp-protocol-version"] == MODERN
            assert request.headers["mcp-method"] == body["method"]
            assert "mcp-session-id" not in request.headers
        call = next(r for r in server.requests if json.loads(r.content)["method"] == "tools/call")
        assert call.headers["mcp-name"] == "search"
        assert await handler.health_check() is True

    async def test_a_tool_name_outside_plain_ascii_goes_base64(self) -> None:
        server = ModernServer()
        await _handler(server).send("x", tool_name="seárch\n", arguments={})
        header = server.requests[-1].headers["mcp-name"]
        assert header == "=?base64?" + base64.b64encode("seárch\n".encode()).decode() + "?="

    async def test_unknown_versions_only_fail_and_name_them(self) -> None:
        server = ModernServer(supported=["2027-01-01"])
        handler = _handler(server)
        with pytest.raises(ProtocolError, match="2027-01-01"):
            await handler._jsonrpc_call("tools/list", {})
        with pytest.raises(ProtocolError, match="2027-01-01"):
            await handler._jsonrpc_call("tools/list", {})
        assert await handler.health_check() is False
        assert [b["method"] for b in server.bodies] == ["server/discover"]  # decided once

    async def test_a_modern_rejection_is_an_error_not_a_fallback(self) -> None:
        seen: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content)["method"])
            error = {"code": -32021, "message": "Missing required client capability"}
            return httpx.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": error})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        with pytest.raises(ProtocolError, match="-32021"):
            await handler._jsonrpc_call("tools/list", {})
        assert seen == ["server/discover"]

    async def test_a_dual_era_server_offering_a_legacy_version_gets_initialize(self) -> None:
        legacy = LegacyServer("2025-06-18")

        def handle(request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["method"] == "server/discover":
                legacy.requests.append(request)
                data = {"supported": ["2025-06-18"], "requested": MODERN}
                error = {"code": -32022, "message": "Unsupported protocol version", "data": data}
                return httpx.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": error})
            return legacy.handle(request)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        assert [c["name"] for c in await handler.discover()] == ["search", "login"]
        init = legacy.bodies[1]
        assert init["method"] == "initialize"
        assert init["params"]["protocolVersion"] == "2025-06-18"
        assert legacy.requests[-1].headers["mcp-protocol-version"] == "2025-06-18"


class TestLegacyServers:
    async def test_2024_server_falls_back_to_todays_requests(self) -> None:
        server = LegacyServer("2024-11-05")
        handler = _handler(server)
        caps = await handler.discover()
        reply = await handler.send("hello")
        tool = await handler.send("x", tool_name="search", arguments={"q": "a"})
        assert [c["name"] for c in caps] == ["search", "login"]
        assert reply["content"] == "legacy reply: hello"
        assert tool["content"] == "legacy tool search"
        assert tool["tool_calls"] == [{"name": "search", "arguments": {"q": "a"}}]
        methods = [b["method"] for b in server.bodies]
        assert methods[:3] == ["server/discover", "initialize", "notifications/initialized"]
        assert server.bodies[1]["params"]["protocolVersion"] == "2025-11-25"
        later = list(zip(server.requests, server.bodies, strict=True))[3:]
        # after the handshake: today's bodies, no _meta and no version header
        assert [b["params"] for _, b in later[:3]] == [{}, {}, {}]
        assert later[3][1]["params"] == {
            "messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}]
        }
        assert later[4][1]["params"] == {"name": "search", "arguments": {"q": "a"}}
        for request, _ in later:
            assert "mcp-protocol-version" not in request.headers
        assert await handler.health_check() is True

    async def test_2025_server_gets_its_session_and_version_header(self) -> None:
        server = LegacyServer("2025-11-25", sessions=True)
        handler = _handler(server)
        assert [c["name"] for c in await handler.discover()] == ["search", "login"]  # SSE body
        assert (await handler.send("hi"))["content"] == "legacy reply: hi"
        for request in server.requests[2:]:
            assert request.headers["mcp-session-id"] == "sess-1"
            assert request.headers["mcp-protocol-version"] == "2025-11-25"
            assert "text/event-stream" in request.headers["accept"]

    async def test_a_server_without_initialize_still_gets_bare_requests(self) -> None:
        async def handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if body["method"] == "tools/list":
                result = {"tools": [{"name": "search"}]}
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})
            error = {"code": -32601, "message": "no such method"}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": error})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        assert [c["name"] for c in await handler.discover()] == ["search"]
        assert await handler.health_check() is False

    async def test_an_unknown_legacy_version_gets_no_version_header(self) -> None:
        server = LegacyServer("1999-01-01\r\nX-Injected: 1")
        handler = _handler(server)
        await handler.discover()
        assert all("mcp-protocol-version" not in r.headers for r in server.requests[2:])


class TestInputRequired:
    async def test_a_foreign_url_is_recorded_flagged_and_declined(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        server = ModernServer(elicit_url="https://evil.example.net/phish")
        with caplog.at_level("WARNING"):
            result = await _handler(server).send("x", tool_name="login", arguments={})
        [record] = result["metadata"]["mcp_input_required"]
        assert record == {
            "key": "signin",
            "mode": "url",
            "message": "Sign in to continue",
            "url": "https://evil.example.net/phish",
            "url_host": "evil.example.net",
            "foreign_host": True,
        }
        assert result["content"].startswith("modern tool login")
        assert "https://evil.example.net/phish" in result["content"]
        assert "not the server host" in result["content"]
        calls = [b for b in server.bodies if b["method"] == "tools/call"]
        assert len(calls) == 2
        assert calls[1]["params"]["inputResponses"] == {"signin": {"action": "decline"}}
        assert calls[1]["params"]["requestState"] == "s1"
        assert calls[1]["params"]["_meta"][_META] == MODERN
        hosts = [
            r.args[1] for r in caplog.records if isinstance(r.args, tuple) and len(r.args) == 2
        ]
        assert hosts == ["evil.example.net"]  # the logged host, compared whole

    async def test_a_same_host_url_is_recorded_unflagged(self) -> None:
        server = ModernServer(elicit_url="https://MCP.example.com/auth")
        result = await _handler(server).send("x", tool_name="login", arguments={})
        [record] = result["metadata"]["mcp_input_required"]
        assert record["url_host"] == "mcp.example.com" and record["foreign_host"] is False
        assert "not the server host" not in result["content"]

    @pytest.mark.parametrize("url", ["javascript:alert(1)", "https://[::1/x", "not a url"])
    async def test_a_url_without_a_readable_host_is_flagged(self, url: str) -> None:
        result = await _handler(ModernServer(elicit_url=url)).send(
            "x", tool_name="login", arguments={}
        )
        [record] = result["metadata"]["mcp_input_required"]
        assert record["url"] == url and record["foreign_host"] is True

    async def test_a_server_that_asks_again_gets_one_retry_only(self) -> None:
        server = ModernServer(reask=True)
        result = await _handler(server).send("x", tool_name="login", arguments={})
        assert len([b for b in server.bodies if b["method"] == "tools/call"]) == 2
        assert result["metadata"]["mcp_input_required"][0]["foreign_host"] is True
        assert "https://evil.example.net/phish" in result["content"]

    async def test_a_request_ziran_cannot_answer_is_not_retried(self) -> None:
        server = ModernServer()

        def handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if body["method"] != "tools/call":
                return server.handle(request)
            server.requests.append(request)
            sampling = {"method": "sampling/createMessage", "params": {"messages": []}}
            result = {"resultType": "input_required", "inputRequests": {"llm": sampling}}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        result = await handler.send("x", tool_name="login", arguments={})
        assert result["content"] == "" and "mcp_input_required" not in result["metadata"]
        assert len([b for b in server.bodies if b["method"] == "tools/call"]) == 1

    async def test_the_chat_path_follows_input_required(self) -> None:
        result = await _handler(ModernServer()).send("please LOGIN")
        assert result["content"].startswith("modern reply: please LOGIN")
        assert result["metadata"]["mcp_input_required"][0]["url_host"] == "evil.example.net"


class TestBodies:
    async def test_a_body_nested_too_deep_is_a_protocol_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def deep(self: httpx.Response, **kwargs: Any) -> Any:
            raise RecursionError("maximum recursion depth exceeded")

        handler = _handler(LegacyServer())
        await handler.health_check()
        monkeypatch.setattr(httpx.Response, "json", deep)
        with pytest.raises(ProtocolError, match="not JSON"):
            await handler._jsonrpc_call("tools/list", {})

    async def test_an_sse_body_without_the_answer_is_empty(self) -> None:
        async def handle(request: httpx.Request) -> httpx.Response:
            stream = 'data: {"jsonrpc": "2.0", "method": "notifications/progress"}\n\ndata: [\n\n'
            return httpx.Response(200, text=stream, headers={"content-type": "text/event-stream"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        with pytest.raises(ProtocolError, match="not JSON"):
            await handler._jsonrpc_call("tools/list", {})

    async def test_an_sse_answer_after_a_malformed_event_is_read(self) -> None:
        async def handle(request: httpx.Request) -> httpx.Response:
            rid = json.loads(request.content).get("id")
            answer = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "s"}]}})
            stream = f"data: [\n\nevent: message\ndata: {answer}\n\n"
            return httpx.Response(200, text=stream, headers={"content-type": "text/event-stream"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        handler = MCPProtocolHandler(client, TargetConfig(url=URL))
        assert await handler._jsonrpc_call("tools/list", {}) == {"tools": [{"name": "s"}]}


class TestAutoDetection:
    @pytest.mark.parametrize("server", [ModernServer(), LegacyServer()])
    async def test_both_eras_are_detected_as_mcp(self, server: ModernServer | LegacyServer) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        async def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(404)
            return server.handle(request)

        adapter = HttpAgentAdapter(TargetConfig(url=URL, protocol="auto"))
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        assert await adapter._auto_detect_protocol() == ProtocolType.MCP
