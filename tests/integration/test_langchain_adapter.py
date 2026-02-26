"""Integration tests — LangChainAdapter with a fake LLM.

Uses LangChain's FakeListLLM so no real API calls are needed.
Requires the ``langchain`` extra to be installed.
"""

from __future__ import annotations

from typing import Any

import pytest

try:
    import langchain  # noqa: F401

    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _HAS_LANGCHAIN, reason="langchain extras not installed"),
]


def _build_agent_executor() -> Any:
    """Build a minimal ReAct agent backed by FakeListLLM."""
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain_community.llms.fake import FakeListLLM
    from langchain_core.prompts import PromptTemplate
    from langchain_core.tools import tool as lc_tool

    @lc_tool  # type: ignore[misc]
    def calculator(expression: str) -> str:
        """Evaluate a mathematical expression."""
        return str(eval(expression))

    @lc_tool  # type: ignore[misc]
    def search_web(query: str) -> str:
        """Search the web for information."""
        return f"Results for: {query}"

    tools = [calculator, search_web]
    llm = FakeListLLM(
        responses=[
            "I now know the final answer.\nFinal Answer: 42",
            "I need to calculate.\nAction: calculator\nAction Input: 2+2\n",
            "Final Answer: 4",
        ]
    )
    prompt_text = (
        "Answer the following questions as best you can. "
        "You have access to the following tools:\n\n"
        "{tools}\n\n"
        "Use the following format:\n\n"
        "Question: the input question\n"
        "Thought: you should always think about what to do\n"
        "Action: the action to take, should be one of [{tool_names}]\n"
        "Action Input: the input to the action\n"
        "Observation: the result of the action\n"
        "... (this Thought/Action/Action Input/Observation can repeat N times)\n"
        "Thought: I now know the final answer\n"
        "Final Answer: the final answer to the original input question\n\n"
        "Begin!\n\n"
        "Question: {input}\n"
        "Thought:{agent_scratchpad}"
    )
    prompt = PromptTemplate.from_template(prompt_text)
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, handle_parsing_errors=True)


class TestLangChainAdapterIntegration:
    """Integration tests for LangChainAdapter with a real LangChain agent."""

    async def test_discover_capabilities(self) -> None:
        from ziran.domain.entities.capability import CapabilityType
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        executor = _build_agent_executor()
        adapter = LangChainAdapter(executor)

        caps = await adapter.discover_capabilities()
        assert len(caps) == 2
        names = {c.name for c in caps}
        assert "calculator" in names
        assert "search_web" in names
        assert all(c.type == CapabilityType.TOOL for c in caps)

    async def test_invoke_returns_response(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        executor = _build_agent_executor()
        adapter = LangChainAdapter(executor)

        response = await adapter.invoke("What is 2+2?")
        assert response.content  # non-empty
        assert isinstance(response.content, str)

    async def test_state_tracking(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        executor = _build_agent_executor()
        adapter = LangChainAdapter(executor)

        await adapter.invoke("Hello")
        state = adapter.get_state()
        assert len(state.conversation_history) >= 2  # user + assistant

        adapter.reset_state()
        state = adapter.get_state()
        assert len(state.conversation_history) == 0
