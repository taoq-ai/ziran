"""Integration tests — BedrockAdapter with mocked boto3.

Uses unittest.mock to patch boto3, exercising the adapter's full
discover → invoke cycle without real AWS credentials.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ziran.domain.interfaces.adapter import AgentResponse

pytestmark = pytest.mark.integration


def _mock_boto3_session() -> tuple[MagicMock, MagicMock, MagicMock]:
    """Create a mock boto3 session with runtime and management clients."""
    mock_boto3 = MagicMock()
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    runtime_client = MagicMock()
    mgmt_client = MagicMock()

    def _client_factory(service: str) -> MagicMock:
        if service == "bedrock-agent-runtime":
            return runtime_client
        if service == "bedrock-agent":
            return mgmt_client
        return MagicMock()

    mock_session.client.side_effect = _client_factory
    return mock_boto3, runtime_client, mgmt_client


def _make_invoke_response(text: str) -> dict:
    """Build a mock invoke_agent response."""
    return {
        "completion": [
            {"chunk": {"bytes": text.encode("utf-8")}},
        ]
    }


class TestBedrockAdapterIntegration:
    """Integration tests for Bedrock adapter with mocked AWS."""

    def _make_adapter(
        self,
        mock_boto3: MagicMock,
        agent_id: str = "test-agent-id",
        agent_alias_id: str = "test-alias",
    ) -> Any:
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter

            return BedrockAdapter(
                agent_id=agent_id,
                agent_alias_id=agent_alias_id,
                region="us-east-1",
            )

    async def test_discover_capabilities_with_action_groups(self) -> None:
        mock_boto3, _runtime_client, mgmt_client = _mock_boto3_session()

        # Agent versions
        mgmt_client.list_agent_versions.return_value = {
            "agentVersionSummaries": [{"agentVersion": "1"}]
        }
        # Action groups
        mgmt_client.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {
                    "actionGroupId": "ag1",
                    "actionGroupName": "search_database",
                    "description": "Search operations",
                },
                {
                    "actionGroupId": "ag2",
                    "actionGroupName": "send_email",
                    "description": "Email operations",
                },
            ]
        }

        adapter = self._make_adapter(mock_boto3)
        caps = await adapter.discover_capabilities()

        assert len(caps) == 2
        names = {c.name for c in caps}
        assert "search_database" in names
        assert "send_email" in names

    async def test_invoke_returns_response(self) -> None:
        mock_boto3, runtime_client, _mgmt_client = _mock_boto3_session()

        runtime_client.invoke_agent.return_value = _make_invoke_response(
            "I can help with that request."
        )

        adapter = self._make_adapter(mock_boto3)
        response = await adapter.invoke("What can you do?")

        assert isinstance(response, AgentResponse)
        assert "help" in response.content.lower()

    async def test_state_management(self) -> None:
        mock_boto3, runtime_client, _mgmt_client = _mock_boto3_session()

        runtime_client.invoke_agent.return_value = _make_invoke_response("Hello!")

        adapter = self._make_adapter(mock_boto3)
        await adapter.invoke("Hi")

        state = adapter.get_state()
        assert len(state.conversation_history) >= 2

        adapter.reset_state()
        state = adapter.get_state()
        assert len(state.conversation_history) == 0
