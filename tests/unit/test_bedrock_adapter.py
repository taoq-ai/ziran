"""Unit tests for the BedrockAdapter."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ziran.domain.entities.capability import CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_mock_boto3() -> MagicMock:
    """Create a mock boto3 module with runtime and management clients."""
    mock_boto3 = MagicMock()
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    runtime_client = MagicMock()
    mgmt_client = MagicMock()

    def _client_factory(service: str) -> MagicMock:
        if service == "bedrock-agent-runtime":
            return runtime_client
        elif service == "bedrock-agent":
            return mgmt_client
        return MagicMock()

    mock_session.client.side_effect = _client_factory
    return mock_boto3


def _make_invoke_response(text: str, tool_calls: list | None = None) -> dict:
    """Build a mock invoke_agent response with streaming chunks."""
    chunks = [
        {"chunk": {"bytes": text.encode("utf-8")}},
    ]
    if tool_calls:
        for tc in tool_calls:
            chunks.append(
                {
                    "trace": {
                        "trace": {
                            "orchestrationTrace": {
                                "invocationInput": {
                                    "actionGroupInvocationInput": {
                                        "actionGroupName": tc["name"],
                                        "function": tc.get("function", ""),
                                        "parameters": tc.get("parameters", []),
                                        "apiPath": tc.get("api_path", ""),
                                    }
                                }
                            }
                        }
                    }
                }
            )
    return {"completion": chunks}


# ──────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBedrockAdapter:
    """Tests for the BedrockAdapter."""

    @pytest.fixture
    def mock_boto3(self) -> MagicMock:
        return _make_mock_boto3()

    @pytest.fixture
    def adapter(self, mock_boto3: MagicMock) -> Any:
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter

            adapter = BedrockAdapter(
                agent_id="AGENT123",
                agent_alias_id="ALIAS456",
                region_name="us-east-1",
            )
        return adapter

    def test_init_stores_config(self, adapter: Any) -> None:
        assert adapter.agent_id == "AGENT123"
        assert adapter.agent_alias_id == "ALIAS456"

    def test_init_creates_session_id(self, adapter: Any) -> None:
        assert adapter._session_id is not None
        assert len(adapter._session_id) > 0

    async def test_invoke_returns_agent_response(self, adapter: Any) -> None:
        adapter._runtime_client.invoke_agent.return_value = _make_invoke_response(
            "Hello from Bedrock!"
        )

        response = await adapter.invoke("Hi")

        assert isinstance(response, AgentResponse)
        assert response.content == "Hello from Bedrock!"
        assert response.metadata["agent_id"] == "AGENT123"
        assert response.metadata["protocol"] == "bedrock-agent"

    async def test_invoke_passes_correct_params(self, adapter: Any) -> None:
        adapter._runtime_client.invoke_agent.return_value = _make_invoke_response("OK")

        await adapter.invoke("Test message")

        adapter._runtime_client.invoke_agent.assert_called_once()
        call_kwargs = adapter._runtime_client.invoke_agent.call_args[1]
        assert call_kwargs["agentId"] == "AGENT123"
        assert call_kwargs["agentAliasId"] == "ALIAS456"
        assert call_kwargs["inputText"] == "Test message"

    async def test_invoke_parses_tool_calls(self, adapter: Any) -> None:
        adapter._runtime_client.invoke_agent.return_value = _make_invoke_response(
            "Done",
            tool_calls=[{"name": "search_db", "function": "search", "parameters": []}],
        )

        response = await adapter.invoke("Search for data")

        assert len(response.tool_calls) == 1
        assert response.tool_calls[0]["tool"] == "search_db"

    async def test_invoke_updates_conversation_history(self, adapter: Any) -> None:
        adapter._runtime_client.invoke_agent.return_value = _make_invoke_response("Response")

        await adapter.invoke("Hello")

        state = adapter.get_state()
        assert len(state.conversation_history) == 2
        assert state.conversation_history[0]["role"] == "user"
        assert state.conversation_history[0]["content"] == "Hello"
        assert state.conversation_history[1]["role"] == "assistant"
        assert state.conversation_history[1]["content"] == "Response"

    async def test_discover_capabilities_action_groups(self, adapter: Any) -> None:
        adapter._mgmt_client.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {
                    "actionGroupId": "ag-001",
                    "actionGroupName": "SearchDB",
                    "description": "Search the database",
                },
                {
                    "actionGroupId": "ag-002",
                    "actionGroupName": "ExecuteCode",
                    "description": "Run arbitrary code",
                },
            ],
        }
        adapter._mgmt_client.list_agent_knowledge_bases.return_value = {
            "agentKnowledgeBaseSummaries": [],
        }

        capabilities = await adapter.discover_capabilities()

        assert len(capabilities) == 2
        assert capabilities[0].name == "SearchDB"
        assert capabilities[0].type == CapabilityType.TOOL
        # "ExecuteCode" should be flagged as dangerous
        assert capabilities[1].dangerous is True

    async def test_discover_capabilities_knowledge_bases(self, adapter: Any) -> None:
        adapter._mgmt_client.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [],
        }
        adapter._mgmt_client.list_agent_knowledge_bases.return_value = {
            "agentKnowledgeBaseSummaries": [
                {
                    "knowledgeBaseId": "kb-001",
                    "description": "Company policies",
                },
            ],
        }

        capabilities = await adapter.discover_capabilities()

        assert len(capabilities) == 1
        assert capabilities[0].type == CapabilityType.DATA_ACCESS
        assert capabilities[0].dangerous is False

    async def test_discover_handles_api_errors(self, adapter: Any) -> None:
        adapter._mgmt_client.list_agent_action_groups.side_effect = Exception("API error")
        adapter._mgmt_client.list_agent_knowledge_bases.side_effect = Exception("API error")

        capabilities = await adapter.discover_capabilities()

        assert capabilities == []

    def test_get_state(self, adapter: Any) -> None:
        state = adapter.get_state()
        assert state.session_id == adapter._session_id
        assert state.memory["agent_id"] == "AGENT123"

    def test_reset_state(self, adapter: Any) -> None:
        adapter._conversation_history.append({"role": "user", "content": "old"})
        old_session = adapter._session_id

        adapter.reset_state()

        assert len(adapter._conversation_history) == 0
        assert adapter._session_id != old_session  # New session ID

    def test_observe_tool_call(self, adapter: Any) -> None:
        adapter.observe_tool_call("my_tool", {"param": "value"}, "result")

        assert len(adapter._observed_tool_calls) == 1
        assert adapter._observed_tool_calls[0]["tool"] == "my_tool"


@pytest.mark.unit
class TestBedrockImportGuard:
    """Tests for boto3 import error handling."""

    def test_import_error_without_boto3(self) -> None:
        with patch.dict("sys.modules", {"boto3": None}):
            from ziran.infrastructure.adapters.bedrock_adapter import _import_boto3

            with pytest.raises(ImportError, match="boto3 is required"):
                _import_boto3()
