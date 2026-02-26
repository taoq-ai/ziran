"""Unit tests for the AgentCoreAdapter."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ziran.domain.entities.capability import CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.adapters.agentcore_adapter import AgentCoreAdapter

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _sync_entrypoint(payload: dict) -> dict:
    """Simple sync entrypoint returning echoed content."""
    return {"result": f"Echo: {payload.get('prompt', '')}"}


async def _async_entrypoint(payload: dict) -> dict:
    """Simple async entrypoint."""
    return {"result": f"Async echo: {payload.get('prompt', '')}"}


def _entrypoint_with_tools(payload: dict) -> dict:
    """Entrypoint returning tool calls."""
    return {
        "result": "Done with tools",
        "tool_calls": [
            {"name": "search", "input": {"q": "test"}, "output": "found"},
            {"name": "email", "input": {"to": "user"}, "output": "sent"},
        ],
    }


def _string_entrypoint(payload: dict) -> str:
    """Entrypoint returning a raw string."""
    return f"Raw: {payload.get('prompt', '')}"


# ──────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAgentCoreAdapterInvoke:
    """Tests for AgentCoreAdapter.invoke()."""

    async def test_sync_entrypoint(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint)
        response = await adapter.invoke("Hello")

        assert isinstance(response, AgentResponse)
        assert response.content == "Echo: Hello"
        assert response.metadata["protocol"] == "agentcore"

    async def test_async_entrypoint(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_async_entrypoint)
        response = await adapter.invoke("Hello")

        assert response.content == "Async echo: Hello"

    async def test_custom_request_response_fields(self) -> None:
        def custom_fn(payload: dict) -> dict:
            return {"output": f"Got: {payload['input']}"}

        adapter = AgentCoreAdapter(
            entrypoint=custom_fn,
            request_field="input",
            response_field="output",
        )
        response = await adapter.invoke("Hi")

        assert response.content == "Got: Hi"

    async def test_tool_calls_parsed(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_entrypoint_with_tools)
        response = await adapter.invoke("Do things")

        assert len(response.tool_calls) == 2
        assert response.tool_calls[0]["tool"] == "search"
        assert response.tool_calls[1]["tool"] == "email"

    async def test_string_response(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_string_entrypoint)
        response = await adapter.invoke("Hello")

        assert response.content == "Raw: Hello"
        assert response.tool_calls == []

    async def test_kwargs_merged_into_payload(self) -> None:
        received_payloads: list[dict] = []

        def capturing_fn(payload: dict) -> dict:
            received_payloads.append(payload)
            return {"result": "ok"}

        adapter = AgentCoreAdapter(entrypoint=capturing_fn)
        await adapter.invoke("Test", extra_field="extra_value")

        assert received_payloads[0]["prompt"] == "Test"
        assert received_payloads[0]["extra_field"] == "extra_value"

    async def test_conversation_history_updated(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint)
        await adapter.invoke("First")
        await adapter.invoke("Second")

        state = adapter.get_state()
        assert len(state.conversation_history) == 4  # 2 turns x 2 messages


@pytest.mark.unit
class TestAgentCoreAdapterCapabilities:
    """Tests for AgentCoreAdapter.discover_capabilities()."""

    async def test_no_app_returns_empty(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint, app=None)
        caps = await adapter.discover_capabilities()
        assert caps == []

    async def test_discover_from_dict_tools(self) -> None:
        mock_app = MagicMock()
        tool_a = MagicMock()
        tool_a.name = "search"
        tool_a.description = "Search the web"
        del tool_a.input_schema  # Ensure no input_schema attr

        tool_b = MagicMock()
        tool_b.name = "execute_shell"
        tool_b.description = "Run shell commands"
        del tool_b.input_schema

        mock_app.tools = {"search": tool_a, "execute_shell": tool_b}

        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint, app=mock_app)
        caps = await adapter.discover_capabilities()

        assert len(caps) == 2
        assert caps[0].name == "search"
        assert caps[0].type == CapabilityType.TOOL
        assert caps[0].dangerous is False
        # "execute_shell" contains "execute" and "shell" → dangerous
        assert caps[1].name == "execute_shell"
        assert caps[1].dangerous is True

    async def test_discover_from_list_tools(self) -> None:
        mock_app = MagicMock()
        tool = MagicMock()
        tool.name = "database_query"
        tool.description = "Query a database"
        del tool.input_schema

        mock_app.tools = [tool]

        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint, app=mock_app)
        caps = await adapter.discover_capabilities()

        assert len(caps) == 1
        assert caps[0].name == "database_query"
        assert caps[0].dangerous is False  # "database" is medium-risk (query), not dangerous


@pytest.mark.unit
class TestAgentCoreAdapterState:
    """Tests for state management."""

    async def test_get_state(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint)
        await adapter.invoke("Hello")

        state = adapter.get_state()
        assert state.session_id is not None
        assert len(state.conversation_history) == 2

    async def test_reset_state(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint)
        await adapter.invoke("Hello")
        adapter.observe_tool_call("test_tool", {"k": "v"}, "output")

        adapter.reset_state()

        state = adapter.get_state()
        assert len(state.conversation_history) == 0
        assert len(adapter._observed_tool_calls) == 0

    def test_observe_tool_call(self) -> None:
        adapter = AgentCoreAdapter(entrypoint=_sync_entrypoint)
        adapter.observe_tool_call("my_tool", {"p": "1"}, "result")

        assert len(adapter._observed_tool_calls) == 1
        assert adapter._observed_tool_calls[0]["tool"] == "my_tool"
        assert adapter._observed_tool_calls[0]["output"] == "result"
