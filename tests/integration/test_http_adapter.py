"""Integration tests — HttpAgentAdapter with httpx mock transport.

Uses httpx.MockTransport to simulate a REST agent endpoint without
real network I/O.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ziran.domain.entities.target import ProtocolType, RestConfig, TargetConfig
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

pytestmark = pytest.mark.integration


def _mock_handler(request: httpx.Request) -> httpx.Response:
    """Simulate a simple REST agent."""
    body: dict[str, Any] = {}
    if request.content:
        body = json.loads(request.content)

    prompt = body.get("message", body.get("prompt", ""))

    # Simulate discovery response
    if "capabilities" in prompt.lower() or "tools" in prompt.lower():
        return httpx.Response(
            200,
            json={
                "response": (
                    "I have the following tools: search_database (search records), "
                    "send_email (send emails), calculator (math operations)."
                )
            },
        )

    # Default response
    return httpx.Response(
        200,
        json={"response": f"I received your message: {prompt[:50]}"},
    )


def _make_config() -> TargetConfig:
    return TargetConfig(
        url="https://agent.test.local/api/chat",
        protocol=ProtocolType.REST,
        rest=RestConfig(
            method="POST",
            body_template={"message": "{prompt}"},
            response_path="response",
        ),
    )


class TestHttpAdapterIntegration:
    """Integration tests for HTTP adapter with mock transport."""

    async def test_invoke_basic(self) -> None:
        config = _make_config()
        adapter = HttpAgentAdapter(config)

        # Inject mock transport
        adapter._client = httpx.AsyncClient(
            transport=httpx.MockTransport(_mock_handler),
            base_url="https://agent.test.local",
        )
        # Force handler creation
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        adapter._handler = RestProtocolHandler(adapter._client, config)
        adapter._session_id = "test-session"

        response = await adapter.invoke("Hello, agent!")
        assert response.content
        assert "received" in response.content.lower()

    async def test_state_tracking(self) -> None:
        config = _make_config()
        adapter = HttpAgentAdapter(config)
        adapter._client = httpx.AsyncClient(
            transport=httpx.MockTransport(_mock_handler),
            base_url="https://agent.test.local",
        )
        from ziran.infrastructure.adapters.protocols.rest_handler import RestProtocolHandler

        adapter._handler = RestProtocolHandler(adapter._client, config)
        adapter._session_id = "test-session"

        await adapter.invoke("First message")
        await adapter.invoke("Second message")

        state = adapter.get_state()
        assert len(state.conversation_history) == 4  # 2 user + 2 assistant

        adapter.reset_state()
        state = adapter.get_state()
        assert len(state.conversation_history) == 0

    async def test_observe_tool_call(self) -> None:
        config = _make_config()
        adapter = HttpAgentAdapter(config)

        adapter.observe_tool_call(
            "search_database",
            {"query": "test"},
            "3 results found",
        )

        assert len(adapter._tool_observations) == 1
        assert adapter._tool_observations[0]["tool"] == "search_database"
