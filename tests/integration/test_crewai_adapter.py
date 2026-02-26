"""Integration tests — CrewAI adapter with mocked crew.

CrewAI's Crew requires agent/task definitions but we mock the underlying
LLM calls so no real API access is needed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

try:
    from crewai import Agent, Crew, Task

    _HAS_CREWAI = True
except ImportError:
    _HAS_CREWAI = False

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _HAS_CREWAI, reason="crewai extras not installed"),
]


def _build_mock_crew() -> Any:
    """Build a CrewAI Crew with mocked LLM backend."""
    mock_agent = MagicMock(spec=Agent)
    mock_agent.role = "Security Researcher"
    mock_agent.goal = "Analyze security vulnerabilities"
    mock_agent.backstory = "Expert security researcher"
    mock_agent.tools = []

    mock_task = MagicMock(spec=Task)
    mock_task.description = "Analyze the target"

    mock_crew = MagicMock(spec=Crew)
    mock_crew.agents = [mock_agent]
    mock_crew.tasks = [mock_task]
    mock_crew.kickoff.return_value = "Analysis complete: No vulnerabilities found."

    return mock_crew


class TestCrewAIAdapterIntegration:
    """Integration tests for CrewAIAdapter."""

    async def test_discover_capabilities(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        crew = _build_mock_crew()
        adapter = CrewAIAdapter(crew)

        caps = await adapter.discover_capabilities()
        assert len(caps) >= 1  # at least one per agent

    async def test_invoke(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        crew = _build_mock_crew()
        adapter = CrewAIAdapter(crew)

        response = await adapter.invoke("Analyze security posture")
        assert "Analysis complete" in response.content
        crew.kickoff.assert_called_once()

    async def test_state_lifecycle(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        crew = _build_mock_crew()
        adapter = CrewAIAdapter(crew)

        # Initial state is empty
        state = adapter.get_state()
        assert len(state.conversation_history) == 0

        # After invoke, state has entries
        await adapter.invoke("Hello")
        state = adapter.get_state()
        assert len(state.conversation_history) >= 2

        # After reset, state is empty again
        adapter.reset_state()
        state = adapter.get_state()
        assert len(state.conversation_history) == 0
