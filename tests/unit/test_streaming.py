"""Unit tests for streaming support.

Tests the streaming domain entities and the default fallback
behaviour of the stream() / stream_complete() / stream_send()
methods on adapters, LLM clients, and protocol handlers.
"""

from __future__ import annotations

from typing import Any

from ziran.domain.entities.streaming import AgentResponseChunk, LLMResponseChunk

# ──────────────────────────────────────────────────────────────────────
# Domain entities
# ──────────────────────────────────────────────────────────────────────


class TestAgentResponseChunk:
    """Tests for AgentResponseChunk model."""

    def test_create_minimal(self) -> None:
        chunk = AgentResponseChunk()
        assert chunk.content_delta == ""
        assert chunk.is_final is False

    def test_create_with_content(self) -> None:
        chunk = AgentResponseChunk(content_delta="Hello", is_final=False)
        assert chunk.content_delta == "Hello"
        assert chunk.is_final is False

    def test_final_chunk(self) -> None:
        chunk = AgentResponseChunk(content_delta=".", is_final=True)
        assert chunk.is_final is True

    def test_tool_call_delta(self) -> None:
        chunk = AgentResponseChunk(
            tool_call_delta={"name": "search", "arguments": '{"q": "foo"}'},
        )
        assert chunk.tool_call_delta is not None
        assert chunk.tool_call_delta["name"] == "search"

    def test_metadata(self) -> None:
        chunk = AgentResponseChunk(metadata={"latency_ms": 42})
        assert chunk.metadata["latency_ms"] == 42


class TestLLMResponseChunk:
    """Tests for LLMResponseChunk model."""

    def test_create_minimal(self) -> None:
        chunk = LLMResponseChunk()
        assert chunk.content_delta == ""
        assert chunk.is_final is False

    def test_with_model(self) -> None:
        chunk = LLMResponseChunk(content_delta="hi", model="gpt-4o")
        assert chunk.model == "gpt-4o"


# ──────────────────────────────────────────────────────────────────────
# Adapter stream() fallback
# ──────────────────────────────────────────────────────────────────────


class TestAdapterStreamFallback:
    """Tests that BaseAgentAdapter.stream() falls back to invoke()."""

    async def test_stream_fallback(self) -> None:
        """Non-streaming adapter should yield a single final chunk."""
        from tests.conftest import MockAgentAdapter

        adapter = MockAgentAdapter(responses=["Hello world"])

        chunks: list[AgentResponseChunk] = []
        async for chunk in adapter.stream("Hi"):
            chunks.append(chunk)

        assert len(chunks) == 1
        assert chunks[0].content_delta == "Hello world"
        assert chunks[0].is_final is True


# ──────────────────────────────────────────────────────────────────────
# LLM client stream_complete() fallback
# ──────────────────────────────────────────────────────────────────────


class TestLLMClientStreamFallback:
    """Tests that BaseLLMClient.stream_complete() falls back to complete()."""

    async def test_stream_complete_fallback(self) -> None:
        from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

        class StubLLMClient(BaseLLMClient):
            async def complete(
                self,
                messages: list[dict[str, str]],
                *,
                temperature: float | None = None,
                max_tokens: int | None = None,
                **kwargs: Any,
            ) -> LLMResponse:
                return LLMResponse(
                    content="result",
                    model="stub",
                    prompt_tokens=1,
                    completion_tokens=2,
                    total_tokens=3,
                )

            async def health_check(self) -> bool:
                return True

        client = StubLLMClient(config=LLMConfig(model="stub"))
        chunks: list[LLMResponseChunk] = []
        async for chunk in client.stream_complete(
            [{"role": "user", "content": "hi"}],
        ):
            chunks.append(chunk)

        assert len(chunks) == 1
        assert chunks[0].content_delta == "result"
        assert chunks[0].is_final is True
        assert chunks[0].model == "stub"


# ──────────────────────────────────────────────────────────────────────
# Protocol handler stream_send() fallback
# ──────────────────────────────────────────────────────────────────────


class TestProtocolHandlerStreamFallback:
    """Tests that BaseProtocolHandler.stream_send() falls back to send()."""

    async def test_stream_send_fallback(self) -> None:
        import httpx

        from ziran.infrastructure.adapters.protocols import BaseProtocolHandler

        class StubHandler(BaseProtocolHandler):
            async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
                return {"content": "pong", "tool_calls": [], "metadata": {}}

            async def discover(self) -> list[dict[str, Any]]:
                return []

            async def health_check(self) -> bool:
                return True

        # Build a minimal TargetConfig
        from ziran.domain.entities.target import TargetConfig

        config = TargetConfig(url="http://fake", protocol="rest")
        handler = StubHandler(client=httpx.AsyncClient(), config=config)

        chunks: list[AgentResponseChunk] = []
        async for chunk in handler.stream_send("ping"):
            chunks.append(chunk)

        assert len(chunks) == 1
        assert chunks[0].content_delta == "pong"
        assert chunks[0].is_final is True
