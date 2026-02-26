"""Unit tests for protocol handlers and HttpAgentAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from ziran.domain.entities.target import (
    A2AConfig,
    ProtocolType,
    RestConfig,
    TargetConfig,
)
from ziran.infrastructure.adapters.protocols import ProtocolError

# ──────────────────────────────────────────────────────────────────────
# ProtocolError
# ──────────────────────────────────────────────────────────────────────


class TestProtocolError:
    """Tests for ProtocolError exception."""

    def test_basic(self) -> None:
        err = ProtocolError("connection failed")
        assert str(err) == "connection failed"
        assert err.status_code is None

    def test_with_status(self) -> None:
        err = ProtocolError("rate limited", status_code=429)
        assert err.status_code == 429


# ──────────────────────────────────────────────────────────────────────
# RestProtocolHandler
# ──────────────────────────────────────────────────────────────────────


class TestRestProtocolHandler:
    """Tests for the REST protocol handler."""

    @pytest.fixture()
    def config(self) -> TargetConfig:
        return TargetConfig(
            url="https://agent.example.com",
            protocol=ProtocolType.REST,
            rest=RestConfig(
                method="POST",
                request_path="/api/chat",
                message_field="input",
                response_field="output.text",
            ),
        )

    @pytest.fixture()
    def mock_client(self) -> AsyncMock:
        client = AsyncMock(spec=httpx.AsyncClient)
        return client

    def test_builds_correct_request(self, config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        client = AsyncMock(spec=httpx.AsyncClient)
        handler = RestProtocolHandler(client, config)

        # Verify handler stores config
        assert handler._config == config

    @pytest.mark.asyncio()
    async def test_send_post(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"output": {"text": "Hello!"}}
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        handler = RestProtocolHandler(mock_client, config)
        result = await handler.send("Hi")

        assert result["content"] == "Hello!"
        mock_client.request.assert_called_once()

    @pytest.mark.asyncio()
    async def test_send_error_raises(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        mock_client.request.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )  # type: ignore[arg-type]

        handler = RestProtocolHandler(mock_client, config)
        with pytest.raises(ProtocolError):
            await handler.send("Hi")

    @pytest.mark.asyncio()
    async def test_discover_returns_empty(
        self, config: TargetConfig, mock_client: AsyncMock
    ) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        handler = RestProtocolHandler(mock_client, config)
        result = await handler.discover()
        assert result == []

    @pytest.mark.asyncio()
    async def test_health_check(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.request.return_value = mock_response

        handler = RestProtocolHandler(mock_client, config)
        result = await handler.health_check()
        assert result is True


# ──────────────────────────────────────────────────────────────────────
# OpenAIProtocolHandler
# ──────────────────────────────────────────────────────────────────────


class TestOpenAIProtocolHandler:
    """Tests for the OpenAI-compatible protocol handler."""

    @pytest.fixture()
    def config(self) -> TargetConfig:
        return TargetConfig(
            url="https://api.openai.com",
            protocol=ProtocolType.OPENAI,
        )

    @pytest.fixture()
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.mark.asyncio()
    async def test_send_chat_completion(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Hello from GPT!",
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        handler = OpenAIProtocolHandler(mock_client, config)
        result = await handler.send("Hi")

        assert result["content"] == "Hello from GPT!"
        assert result["metadata"]["prompt_tokens"] == 10

    @pytest.mark.asyncio()
    async def test_discover_models(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "gpt-4", "object": "model"},
                {"id": "gpt-3.5-turbo", "object": "model"},
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response

        handler = OpenAIProtocolHandler(mock_client, config)
        caps = await handler.discover()
        assert len(caps) == 2
        assert caps[0]["id"] == "gpt-4"

    def test_reset_conversation(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        handler = OpenAIProtocolHandler(mock_client, config)
        handler._conversation.append({"role": "user", "content": "test"})
        handler.reset_conversation()
        assert len(handler._conversation) == 0


# ──────────────────────────────────────────────────────────────────────
# MCPProtocolHandler
# ──────────────────────────────────────────────────────────────────────


class TestMCPProtocolHandler:
    """Tests for the MCP protocol handler."""

    @pytest.fixture()
    def config(self) -> TargetConfig:
        return TargetConfig(
            url="https://mcp-server.example.com",
            protocol=ProtocolType.MCP,
        )

    @pytest.fixture()
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.mark.asyncio()
    async def test_discover_tools(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search",
                        "description": "Search the web",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        handler = MCPProtocolHandler(mock_client, config)
        caps = await handler.discover()

        # tools/list is the first call, should return tool capabilities
        assert len(caps) >= 1

    @pytest.mark.asyncio()
    async def test_health_check(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test-server"},
            },
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        handler = MCPProtocolHandler(mock_client, config)
        assert await handler.health_check() is True


# ──────────────────────────────────────────────────────────────────────
# A2AProtocolHandler
# ──────────────────────────────────────────────────────────────────────


class TestA2AProtocolHandler:
    """Tests for the A2A protocol handler."""

    @pytest.fixture()
    def config(self) -> TargetConfig:
        return TargetConfig(
            url="https://a2a-agent.example.com",
            protocol=ProtocolType.A2A,
            a2a=A2AConfig(blocking=True),
        )

    @pytest.fixture()
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.mark.asyncio()
    async def test_fetch_agent_card(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "TestA2AAgent",
            "version": "1.0",
            "skills": [{"id": "echo", "name": "Echo", "description": "Echoes input"}],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response

        handler = A2AProtocolHandler(mock_client, config)
        card = await handler.fetch_agent_card()

        assert card.name == "TestA2AAgent"
        assert len(card.skills) == 1

    @pytest.mark.asyncio()
    async def test_discover_maps_skills(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "DiscoverAgent",
            "version": "1.0",
            "skills": [
                {"id": "search", "name": "Search", "description": "Searches things"},
                {"id": "calc", "name": "Calculator", "description": "Does math"},
            ],
            "capabilities": {"streaming": True},
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response

        handler = A2AProtocolHandler(mock_client, config)
        caps = await handler.discover()

        skill_caps = [c for c in caps if c["type"] == "skill"]
        assert len(skill_caps) >= 2
        assert any(c["name"] == "Search" for c in skill_caps)

        # Streaming capability is mapped too
        assert any(c["id"] == "a2a_streaming" for c in caps)

    def test_reset_context(self, config: TargetConfig, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.a2a_handler import A2AProtocolHandler

        handler = A2AProtocolHandler(mock_client, config)
        old_context = handler._context_id
        handler.reset_context()
        assert handler._context_id != old_context


# ──────────────────────────────────────────────────────────────────────
# HttpAgentAdapter
# ──────────────────────────────────────────────────────────────────────


class TestHttpAgentAdapter:
    """Tests for the main HTTP agent adapter."""

    @pytest.fixture()
    def rest_config(self) -> TargetConfig:
        return TargetConfig(
            url="https://agent.example.com",
            protocol=ProtocolType.REST,
            rest=RestConfig(message_field="input", response_field="output"),
        )

    @pytest.mark.asyncio()
    async def test_invoke_delegates_to_handler(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)

        mock_handler = AsyncMock()
        mock_handler.send.return_value = {
            "content": "Test response",
            "tool_calls": [],
            "metadata": {},
        }

        # Inject mock handler
        adapter._client = MagicMock()
        adapter._handler = mock_handler
        adapter._session_id = "test-session"

        response = await adapter.invoke("Hello")
        assert response.content == "Test response"
        mock_handler.send.assert_called_once_with("Hello")

    @pytest.mark.asyncio()
    async def test_conversation_tracking(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)

        mock_handler = AsyncMock()
        mock_handler.send.return_value = {
            "content": "Response 1",
            "tool_calls": [],
            "metadata": {},
        }

        adapter._client = MagicMock()
        adapter._handler = mock_handler
        adapter._session_id = "test"

        await adapter.invoke("Message 1")
        await adapter.invoke("Message 2")

        state = adapter.get_state()
        assert len(state.conversation_history) == 4  # 2 user + 2 assistant

    def test_reset_state(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)
        adapter._conversation = [{"role": "user", "content": "hi"}]
        adapter._tool_observations = [{"tool": "test"}]

        adapter.reset_state()
        assert adapter._conversation == []
        assert adapter._tool_observations == []

    def test_observe_tool_call(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)
        adapter.observe_tool_call("search", {"query": "test"}, ["result1"])
        assert len(adapter._tool_observations) == 1
        assert adapter._tool_observations[0]["tool"] == "search"

    def test_get_state_returns_protocol(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)
        adapter._session_id = "sess-123"
        state = adapter.get_state()
        assert state.session_id == "sess-123"
        assert state.memory["protocol"] == "rest"

    @pytest.mark.asyncio()
    async def test_close_cleanup(self, rest_config: TargetConfig) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(rest_config)
        mock_client = AsyncMock()
        mock_handler = AsyncMock()

        adapter._client = mock_client
        adapter._handler = mock_handler

        await adapter.close()
        mock_handler.close.assert_called_once()
        mock_client.aclose.assert_called_once()
        assert adapter._client is None


# ──────────────────────────────────────────────────────────────────────
# Attack Library Protocol Filtering
# ──────────────────────────────────────────────────────────────────────


class TestAttackLibraryProtocolFilter:
    """Tests for protocol-based filtering in the attack library."""

    def test_protocol_filter_field_on_vector(self) -> None:
        from ziran.domain.entities.attack import AttackVector
        from ziran.domain.entities.phase import ScanPhase

        vector = AttackVector(
            id="test_a2a",
            name="Test A2A Vector",
            category="prompt_injection",
            target_phase=ScanPhase.EXECUTION,
            severity="high",
            description="A2A-specific test vector",
            protocol_filter=["a2a"],
        )
        assert vector.protocol_filter == ["a2a"]

    def test_empty_protocol_filter_matches_all(self) -> None:
        from ziran.domain.entities.attack import AttackVector
        from ziran.domain.entities.phase import ScanPhase

        vector = AttackVector(
            id="test_generic",
            name="Generic Vector",
            category="prompt_injection",
            target_phase=ScanPhase.EXECUTION,
            severity="high",
            description="Works on all protocols",
        )
        assert vector.protocol_filter == []

    def test_library_loads_a2a_vectors(self) -> None:
        from ziran.application.attacks.library import AttackLibrary

        library = AttackLibrary()
        a2a_vectors = library.get_attacks_by_protocol("a2a")
        # Should include both generic vectors and A2A-specific ones
        a2a_specific = [v for v in a2a_vectors if v.protocol_filter == ["a2a"]]
        assert len(a2a_specific) > 0

    def test_library_protocol_filter_excludes(self) -> None:
        from ziran.application.attacks.library import AttackLibrary

        library = AttackLibrary()
        rest_vectors = library.get_attacks_by_protocol("rest")
        # A2A-only vectors should not appear for REST
        for v in rest_vectors:
            if v.protocol_filter:
                assert "rest" in v.protocol_filter

    def test_search_with_protocol(self) -> None:
        from ziran.application.attacks.library import AttackLibrary

        library = AttackLibrary()
        results = library.search(protocol="a2a")
        # Should include generic + A2A-specific vectors
        assert len(results) > 0
        for v in results:
            assert not v.protocol_filter or "a2a" in v.protocol_filter


# ──────────────────────────────────────────────────────────────────────
# OpenAI handler config forwarding
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestOpenAIHandlerConfig:
    """Tests for OpenAIProtocolHandler with temperature/max_tokens."""

    @pytest.fixture()
    def mock_client(self) -> AsyncMock:
        client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "Hi"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
        mock_response.raise_for_status = MagicMock()
        client.post.return_value = mock_response
        return client

    async def test_temperature_in_request(self, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        config = TargetConfig(url="https://api.openai.com", protocol=ProtocolType.OPENAI)
        handler = OpenAIProtocolHandler(mock_client, config, model="gpt-4o", temperature=0.7)

        await handler.send("Hello")

        call_kwargs = mock_client.post.call_args
        body = call_kwargs[1]["json"]
        assert body["temperature"] == 0.7
        assert body["model"] == "gpt-4o"

    async def test_max_tokens_in_request(self, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        config = TargetConfig(url="https://api.openai.com", protocol=ProtocolType.OPENAI)
        handler = OpenAIProtocolHandler(mock_client, config, model="gpt-4o", max_tokens=512)

        await handler.send("Hello")

        body = mock_client.post.call_args[1]["json"]
        assert body["max_tokens"] == 512

    async def test_no_temp_or_max_tokens_omitted(self, mock_client: AsyncMock) -> None:
        from ziran.infrastructure.adapters.protocols.openai_handler import OpenAIProtocolHandler

        config = TargetConfig(url="https://api.openai.com", protocol=ProtocolType.OPENAI)
        handler = OpenAIProtocolHandler(mock_client, config)

        await handler.send("Hello")

        body = mock_client.post.call_args[1]["json"]
        assert "temperature" not in body
        assert "max_tokens" not in body


# ──────────────────────────────────────────────────────────────────────
# Additional HttpAgentAdapter coverage (build_client, auto-detect, retry, probe)
# ──────────────────────────────────────────────────────────────────────


class TestBuildClientExtended:
    """Extra tests for _build_client auth / TLS / proxy paths."""

    def test_bearer_auth_header(self) -> None:
        from ziran.domain.entities.target import AuthConfig, AuthType

        cfg = TargetConfig(
            url="https://x.com",
            auth=AuthConfig(type=AuthType.BEARER, token="tok123"),
        )
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(cfg)
        client = adapter._build_client()
        assert client.headers.get("authorization") == "Bearer tok123"

    def test_api_key_header(self) -> None:
        from ziran.domain.entities.target import AuthConfig, AuthType

        cfg = TargetConfig(
            url="https://x.com",
            auth=AuthConfig(type=AuthType.API_KEY, token="key99", header_name="X-Key"),
        )
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(cfg)
        client = adapter._build_client()
        assert client.headers.get("x-key") == "key99"

    def test_basic_auth(self) -> None:
        from ziran.domain.entities.target import AuthConfig, AuthType

        cfg = TargetConfig(
            url="https://x.com",
            auth=AuthConfig(type=AuthType.BASIC, username="u", password="p"),
        )
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(cfg)
        client = adapter._build_client()
        assert client.auth is not None


class TestAutoDetectProtocol:
    """Tests for _auto_detect_protocol with mock HTTP."""

    async def test_detect_a2a(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        async def _handler(request: httpx.Request) -> httpx.Response:
            if "agent-card" in str(request.url):
                return httpx.Response(200, json={"name": "Agent", "skills": []})
            return httpx.Response(404)

        cfg = TargetConfig(url="https://x.com", protocol="auto")
        adapter = HttpAgentAdapter(cfg)
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        proto = await adapter._auto_detect_protocol()
        assert proto == ProtocolType.A2A

    async def test_detect_openai(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        async def _handler(request: httpx.Request) -> httpx.Response:
            if "/v1/models" in str(request.url):
                return httpx.Response(200, json={"data": [{"id": "gpt-4"}]})
            return httpx.Response(404)

        cfg = TargetConfig(url="https://x.com", protocol="auto")
        adapter = HttpAgentAdapter(cfg)
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        proto = await adapter._auto_detect_protocol()
        assert proto == ProtocolType.OPENAI

    async def test_detect_mcp(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        async def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"result": {"protocolVersion": "2024-11-05"}})
            return httpx.Response(404)

        cfg = TargetConfig(url="https://x.com", protocol="auto")
        adapter = HttpAgentAdapter(cfg)
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        proto = await adapter._auto_detect_protocol()
        assert proto == ProtocolType.MCP

    async def test_fallback_rest(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        cfg = TargetConfig(url="https://x.com", protocol="auto")
        adapter = HttpAgentAdapter(cfg)
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        proto = await adapter._auto_detect_protocol()
        assert proto == ProtocolType.REST


class TestSendWithRetryExtended:
    """Tests for _send_with_retry retry / no-retry / exhaust paths."""

    async def test_success(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(TargetConfig(url="https://x.com"))
        handler = AsyncMock()
        handler.send.return_value = {"content": "ok"}
        adapter._handler = handler
        result = await adapter._send_with_retry("hi")
        assert result["content"] == "ok"

    async def test_retry_then_success(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(TargetConfig(url="https://x.com"))
        handler = AsyncMock()
        handler.send.side_effect = [
            ProtocolError("boom", status_code=429),
            {"content": "recovered"},
        ]
        adapter._handler = handler
        result = await adapter._send_with_retry("hi")
        assert result["content"] == "recovered"

    async def test_no_retry_on_4xx(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(TargetConfig(url="https://x.com"))
        handler = AsyncMock()
        handler.send.side_effect = ProtocolError("bad request", status_code=400)
        adapter._handler = handler
        with pytest.raises(ProtocolError, match="bad request"):
            await adapter._send_with_retry("hi")


class TestProbeDiscoverExtended:
    """Tests for _probe_discover capability extraction."""

    async def test_extracts_capabilities(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(TargetConfig(url="https://x.com"))
        handler = AsyncMock()
        handler.send.return_value = {
            "content": "- search_files: searches files\n- read_database: reads tables\n",
        }
        adapter._handler = handler
        caps = await adapter._probe_discover()
        assert len(caps) >= 1

    async def test_handles_protocol_errors(self) -> None:
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        adapter = HttpAgentAdapter(TargetConfig(url="https://x.com"))
        handler = AsyncMock()
        handler.send.side_effect = ProtocolError("fail")
        adapter._handler = handler
        caps = await adapter._probe_discover()
        assert caps == []
