"""Unit tests for the native Anthropic SDK adapter."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from ziran.domain.entities.capability import CapabilityType
from ziran.infrastructure.adapters.anthropic_adapter import AnthropicAdapter

# ── Helpers ──────────────────────────────────────────────────────────


def _make_text_block(text: str) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _make_tool_block(name: str, tool_input: dict[str, Any], block_id: str = "call_1") -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = name
    block.input = tool_input
    block.id = block_id
    return block


def _make_usage(input_tokens: int = 10, output_tokens: int = 20) -> MagicMock:
    usage = MagicMock()
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    return usage


def _make_response(
    content_blocks: list[MagicMock],
    model: str = "claude-sonnet-4-20250514",
    stop_reason: str = "end_turn",
    usage: MagicMock | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.content = content_blocks
    resp.model = model
    resp.stop_reason = stop_reason
    resp.usage = usage or _make_usage()
    return resp


def _make_sync_client(response: MagicMock) -> MagicMock:
    client = MagicMock()
    client.messages.create.return_value = response
    return client


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAnthropicAdapterInvoke:
    """US1: invoke() returns standardized AgentResponse."""

    @pytest.mark.asyncio
    async def test_text_response(self) -> None:
        response = _make_response([_make_text_block("Hello!")])
        client = _make_sync_client(response)
        adapter = AnthropicAdapter(client=client, model="claude-sonnet-4-20250514")

        result = await adapter.invoke("Hi")

        assert result.content == "Hello!"
        assert result.tool_calls == []
        assert result.prompt_tokens == 10
        assert result.completion_tokens == 20
        assert result.total_tokens == 30
        assert result.metadata["model"] == "claude-sonnet-4-20250514"

    @pytest.mark.asyncio
    async def test_tool_call_response(self) -> None:
        blocks = [
            _make_text_block("Let me check the weather."),
            _make_tool_block("get_weather", {"location": "London"}, "call_123"),
        ]
        response = _make_response(blocks)
        client = _make_sync_client(response)
        adapter = AnthropicAdapter(client=client)

        result = await adapter.invoke("What's the weather?")

        assert result.content == "Let me check the weather."
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0]["tool_name"] == "get_weather"
        assert result.tool_calls[0]["tool_input"] == {"location": "London"}
        assert result.tool_calls[0]["tool_call_id"] == "call_123"

    @pytest.mark.asyncio
    async def test_conversation_history_tracked(self) -> None:
        response = _make_response([_make_text_block("I'm Claude.")])
        client = _make_sync_client(response)
        adapter = AnthropicAdapter(client=client)

        await adapter.invoke("Who are you?")

        state = adapter.get_state()
        assert len(state.conversation_history) == 2
        assert state.conversation_history[0]["role"] == "user"
        assert state.conversation_history[1]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_system_prompt_passed(self) -> None:
        response = _make_response([_make_text_block("OK")])
        client = _make_sync_client(response)
        adapter = AnthropicAdapter(client=client, system_prompt="You are a helpful assistant.")

        await adapter.invoke("Hello")

        call_kwargs = client.messages.create.call_args
        assert call_kwargs.kwargs.get("system") == "You are a helpful assistant."

    @pytest.mark.asyncio
    async def test_tools_passed(self) -> None:
        response = _make_response([_make_text_block("OK")])
        client = _make_sync_client(response)
        tools = [{"name": "read_file", "description": "Read a file", "input_schema": {}}]
        adapter = AnthropicAdapter(client=client, tools=tools)

        await adapter.invoke("Hello")

        call_kwargs = client.messages.create.call_args
        assert call_kwargs.kwargs.get("tools") == tools


@pytest.mark.unit
class TestAnthropicAdapterCapabilities:
    """US1: discover_capabilities() extracts tools."""

    @pytest.mark.asyncio
    async def test_discover_tools(self) -> None:
        client = MagicMock()
        tools = [
            {
                "name": "get_weather",
                "description": "Get weather for a location",
                "input_schema": {"type": "object"},
            },
            {
                "name": "read_file",
                "description": "Read file contents",
                "input_schema": {"type": "object"},
            },
        ]
        adapter = AnthropicAdapter(client=client, tools=tools)

        caps = await adapter.discover_capabilities()

        assert len(caps) == 2
        assert caps[0].name == "get_weather"
        assert caps[0].type == CapabilityType.TOOL
        assert caps[1].name == "read_file"

    @pytest.mark.asyncio
    async def test_no_tools(self) -> None:
        client = MagicMock()
        adapter = AnthropicAdapter(client=client)

        caps = await adapter.discover_capabilities()

        assert caps == []


@pytest.mark.unit
class TestAnthropicAdapterState:
    """US1: State management."""

    def test_reset_state(self) -> None:
        client = MagicMock()
        adapter = AnthropicAdapter(client=client)
        adapter._conversation_history.append({"role": "user", "content": "hi"})
        adapter._observed_tool_calls.append({"tool_name": "x", "inputs": {}, "outputs": None})

        adapter.reset_state()

        state = adapter.get_state()
        assert state.conversation_history == []
        assert state.memory["observed_tool_calls"] == []

    def test_observe_tool_call(self) -> None:
        client = MagicMock()
        adapter = AnthropicAdapter(client=client)

        adapter.observe_tool_call("read_file", {"path": "/etc/passwd"}, "secret data")

        state = adapter.get_state()
        assert len(state.memory["observed_tool_calls"]) == 1
        assert state.memory["observed_tool_calls"][0]["tool_name"] == "read_file"
