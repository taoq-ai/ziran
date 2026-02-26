"""Smoke tests — import-level and basic instantiation for adapter modules.

These tests verify that modules currently excluded from coverage can at
least be imported and minimally instantiated.  They don't exercise real
I/O; every external dependency is mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# ──────────────────────────────────────────────────────────────────────
# LangChain adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLangChainAdapterSmoke:
    """Import and instantiation smoke tests for LangChainAdapter."""

    def test_import(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        assert LangChainAdapter is not None

    def test_instantiation(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        mock_agent = MagicMock()
        mock_agent.tools = []
        adapter = LangChainAdapter(mock_agent)
        assert adapter.agent is mock_agent

    async def test_discover_capabilities_empty(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        mock_agent = MagicMock()
        mock_agent.tools = []
        adapter = LangChainAdapter(mock_agent)
        caps = await adapter.discover_capabilities()
        assert caps == []

    async def test_discover_capabilities_with_tools(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        mock_tool = MagicMock()
        mock_tool.name = "search_web"
        mock_tool.description = "Search the web for information"
        mock_agent = MagicMock()
        mock_agent.tools = [mock_tool]

        adapter = LangChainAdapter(mock_agent)
        caps = await adapter.discover_capabilities()
        assert len(caps) == 1
        assert caps[0].name == "search_web"

    async def test_reset_clears_state(self) -> None:
        from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

        mock_agent = MagicMock()
        mock_agent.tools = []
        adapter = LangChainAdapter(mock_agent)
        adapter.reset_state()
        state = adapter.get_state()
        assert state.conversation_history == []


# ──────────────────────────────────────────────────────────────────────
# CrewAI adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestCrewAIAdapterSmoke:
    """Import and instantiation smoke tests for CrewAIAdapter."""

    def test_import(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        assert CrewAIAdapter is not None

    def test_instantiation(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        mock_crew = MagicMock()
        mock_crew.agents = []
        mock_crew.tasks = []
        adapter = CrewAIAdapter(mock_crew)
        assert adapter.crew is mock_crew

    async def test_discover_capabilities(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        mock_agent = MagicMock()
        mock_agent.role = "Researcher"
        mock_agent.goal = "Find information"
        mock_agent.tools = []

        mock_crew = MagicMock()
        mock_crew.agents = [mock_agent]
        mock_crew.tasks = []

        adapter = CrewAIAdapter(mock_crew)
        caps = await adapter.discover_capabilities()
        # Should have at least one capability per agent
        assert len(caps) >= 1

    async def test_reset_clears_state(self) -> None:
        from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

        mock_crew = MagicMock()
        mock_crew.agents = []
        mock_crew.tasks = []

        adapter = CrewAIAdapter(mock_crew)
        adapter.reset_state()
        state = adapter.get_state()
        assert state.conversation_history == []


# ──────────────────────────────────────────────────────────────────────
# Report generator
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestReportGeneratorSmoke:
    """Import and instantiation smoke tests for ReportGenerator."""

    def test_import(self) -> None:
        from ziran.interfaces.cli.reports import ReportGenerator

        assert ReportGenerator is not None

    def test_instantiation(self, tmp_path: MagicMock) -> None:
        from ziran.interfaces.cli.reports import ReportGenerator

        generator = ReportGenerator(output_dir=tmp_path)
        assert generator.output_dir == tmp_path


# ──────────────────────────────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoggerSmoke:
    """Import and smoke tests for the logging module."""

    def test_import(self) -> None:
        from ziran.infrastructure.logging.logger import get_logger, setup_logging

        assert setup_logging is not None
        assert get_logger is not None

    def test_get_logger_prefixed(self) -> None:
        from ziran.infrastructure.logging.logger import get_logger

        log = get_logger("test_smoke")
        assert log.name == "ziran.test_smoke"

    def test_get_logger_already_prefixed(self) -> None:
        from ziran.infrastructure.logging.logger import get_logger

        log = get_logger("ziran.explicit")
        assert log.name == "ziran.explicit"

    def test_setup_logging_basic(self) -> None:
        from ziran.infrastructure.logging.logger import setup_logging

        # Should not raise
        setup_logging(level="WARNING")
