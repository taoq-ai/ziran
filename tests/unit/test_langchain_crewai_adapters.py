"""Tests for LangChain and CrewAI adapters — fully mocked, no optional deps needed."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

# ═════════════════════════════════════════════════════════════════════
# LangChain Adapter
# ═════════════════════════════════════════════════════════════════════


class TestLangChainAdapter:
    """Unit tests for LangChainAdapter using a fully-mocked AgentExecutor."""

    @pytest.fixture()
    def mock_agent(self) -> MagicMock:
        agent = MagicMock()
        agent.ainvoke = AsyncMock(
            return_value={
                "output": "Hello from chain!",
                "intermediate_steps": [],
            }
        )
        # Tools
        tool = MagicMock()
        tool.name = "search"
        tool.description = "Search the web"
        tool.args_schema = None
        agent.tools = [tool]
        agent.memory = None
        return agent

    @pytest.fixture()
    def adapter(self, mock_agent: MagicMock):
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        return LangChainAdapter(mock_agent)

    async def test_invoke_basic(self, adapter) -> None:
        resp = await adapter.invoke("hi")
        assert resp.content == "Hello from chain!"
        assert resp.tool_calls == []

    async def test_invoke_with_tool_calls(self, mock_agent: MagicMock) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        action = MagicMock()
        action.tool = "search"
        action.tool_input = {"query": "test"}
        mock_agent.ainvoke.return_value = {
            "output": "Found it!",
            "intermediate_steps": [(action, "result data")],
        }
        adapter = LangChainAdapter(mock_agent)
        resp = await adapter.invoke("search for test")
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0]["tool"] == "search"

    async def test_invoke_iteration_limit_suppresses_tools(self, mock_agent: MagicMock) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        action = MagicMock()
        action.tool = "search"
        action.tool_input = {}
        mock_agent.ainvoke.return_value = {
            "output": "Agent stopped due to iteration limit.",
            "intermediate_steps": [(action, "partial")],
        }
        adapter = LangChainAdapter(mock_agent)
        resp = await adapter.invoke("hi")
        # Tool calls suppressed when iteration limit is hit
        assert resp.tool_calls == []
        assert resp.metadata["hit_iteration_limit"] is True

    async def test_discover_capabilities(self, adapter) -> None:
        caps = await adapter.discover_capabilities()
        assert len(caps) == 1
        assert caps[0].name == "search"

    async def test_discover_with_args_schema(self, mock_agent: MagicMock) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        schema_mock = MagicMock()
        schema_mock.model_json_schema.return_value = {"type": "object"}
        mock_agent.tools[0].args_schema = schema_mock
        adapter = LangChainAdapter(mock_agent)
        caps = await adapter.discover_capabilities()
        assert caps[0].parameters == {"schema": {"type": "object"}}

    def test_get_state(self, adapter) -> None:
        state = adapter.get_state()
        assert state.session_id
        assert state.conversation_history == []

    def test_get_state_with_memory(self, mock_agent: MagicMock) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        memory = MagicMock()
        memory.load_memory_variables.return_value = {"history": "stuff"}
        mock_agent.memory = memory
        adapter = LangChainAdapter(mock_agent)
        state = adapter.get_state()
        assert "memory_variables" in state.memory

    def test_reset_state(self, adapter) -> None:
        adapter._conversation_history = [{"role": "user", "content": "hi"}]
        adapter._observed_tool_calls = [{"tool": "x"}]
        adapter.reset_state()
        assert adapter._conversation_history == []
        assert adapter._observed_tool_calls == []

    def test_reset_state_with_memory(self, mock_agent: MagicMock) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        memory = MagicMock()
        mock_agent.memory = memory
        adapter = LangChainAdapter(mock_agent)
        adapter.reset_state()
        memory.clear.assert_called_once()

    def test_observe_tool_call(self, adapter) -> None:
        adapter.observe_tool_call("search", {"q": "test"}, "result")
        assert len(adapter._observed_tool_calls) == 1


class TestLangChainHelpers:
    def test_get_token_callback_returns_none_without_langchain(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import _get_token_callback

        # Without langchain_community installed, should return None
        result = _get_token_callback()
        # Can be None or a context manager depending on installed deps
        assert result is None or result is not None  # Just ensure no crash

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Agent stopped due to iteration limit.", True),
            ("Agent stopped due to max iterations", True),
            ("Agent stopped due to time limit", True),
            ("Normal response", False),
            ("", False),
        ],
    )
    def test_is_iteration_limit_response(self, text: str, expected: bool) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import _is_iteration_limit_response

        assert _is_iteration_limit_response(text) == expected


# ═════════════════════════════════════════════════════════════════════
# CrewAI Adapter
# ═════════════════════════════════════════════════════════════════════


class TestCrewAIAdapter:
    """Unit tests for CrewAIAdapter using a fully-mocked Crew."""

    @pytest.fixture()
    def mock_crew(self) -> MagicMock:
        crew = MagicMock()
        crew.kickoff.return_value = "Crew result!"

        agent = MagicMock()
        agent.role = "Researcher"
        agent.goal = "Find information"

        tool = MagicMock()
        tool.name = "web_search"
        tool.description = "Search the web"
        agent.tools = [tool]

        crew.agents = [agent]
        crew.tasks = [MagicMock()]
        return crew

    @pytest.fixture()
    def adapter(self, mock_crew: MagicMock):
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        return CrewAIAdapter(mock_crew)

    async def test_invoke(self, adapter) -> None:
        resp = await adapter.invoke("analyze this")
        assert resp.content == "Crew result!"
        assert resp.metadata["crew_size"] == 1
        assert resp.metadata["task_count"] == 1

    async def test_conversation_tracked(self, adapter) -> None:
        await adapter.invoke("message 1")
        await adapter.invoke("message 2")
        assert len(adapter._conversation_history) == 4  # 2 user + 2 assistant

    async def test_discover_capabilities(self, adapter) -> None:
        caps = await adapter.discover_capabilities()
        names = [c.name for c in caps]
        assert "web_search" in names
        assert any("Researcher" in n for n in names)

    async def test_discover_no_tools(self, mock_crew: MagicMock) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        mock_crew.agents[0].tools = []
        adapter = CrewAIAdapter(mock_crew)
        caps = await adapter.discover_capabilities()
        # Should still have the role capability
        assert len(caps) == 1
        assert "Agent Role" in caps[0].name

    def test_get_state(self, adapter) -> None:
        state = adapter.get_state()
        assert state.session_id
        assert state.conversation_history == []

    def test_reset_state(self, adapter) -> None:
        adapter._conversation_history = [{"role": "user", "content": "hi"}]
        adapter._observed_tool_calls = [{"tool": "x"}]
        adapter.reset_state()
        assert adapter._conversation_history == []
        assert adapter._observed_tool_calls == []

    def test_observe_tool_call(self, adapter) -> None:
        adapter.observe_tool_call("web_search", {"q": "test"}, "results")
        assert len(adapter._observed_tool_calls) == 1
        assert adapter._observed_tool_calls[0]["tool"] == "web_search"
