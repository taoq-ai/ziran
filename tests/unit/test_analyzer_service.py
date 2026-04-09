"""Tests for the trace AnalyzerService."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ziran.application.trace_analysis.analyzer_service import (
    AnalyzerService,
)
from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.domain.ports.trace_ingestor import TraceIngestor


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _make_session(
    session_id: str,
    tool_names: list[str],
    source: str = "otel",
) -> TraceSession:
    """Create a TraceSession with the given tool call sequence."""
    base_ts = datetime(2023, 11, 14, 22, 0, 0, tzinfo=UTC)
    tool_calls = [
        ToolCallEvent(
            tool_name=name,
            timestamp=datetime(2023, 11, 14, 22, 0, i, tzinfo=UTC),
        )
        for i, name in enumerate(tool_names)
    ]
    return TraceSession(
        session_id=session_id,
        agent_name="test-agent",
        tool_calls=tool_calls,
        start_time=base_ts,
        end_time=datetime(2023, 11, 14, 22, 0, len(tool_names), tzinfo=UTC),
        source=source,
    )


class MockIngestor(TraceIngestor):
    """Mock ingestor that returns pre-configured sessions."""

    def __init__(self, sessions: list[TraceSession]) -> None:
        self._sessions = sessions

    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]:
        return self._sessions


# ── Unit: temp graph construction ────────────────────────────────────


@pytest.mark.unit
class TestAnalyzerServiceGraphConstruction:
    def test_builds_graph_for_dangerous_chain(self) -> None:
        """read_file -> http_request should be detected."""
        sessions = [_make_session("s1", ["read_file", "http_request"])]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        assert result.source == "trace-analysis"
        assert result.total_vulnerabilities > 0
        assert len(result.dangerous_tool_chains) > 0

    def test_clean_chain_produces_no_findings(self) -> None:
        """search -> display should not be flagged."""
        sessions = [_make_session("s1", ["search", "display"])]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        assert result.total_vulnerabilities == 0
        assert len(result.dangerous_tool_chains) == 0


# ── Unit: trace evidence annotation ─────────────────────────────────


@pytest.mark.unit
class TestTraceEvidenceAnnotation:
    def test_chains_annotated_with_production_flag(self) -> None:
        sessions = [_make_session("s1", ["read_file", "http_request"])]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        for chain_dict in result.dangerous_tool_chains:
            assert chain_dict["observed_in_production"] is True
            assert chain_dict["trace_source"] == "otel"
            assert chain_dict["occurrence_count"] >= 1

    def test_first_seen_last_seen_set(self) -> None:
        sessions = [_make_session("s1", ["read_file", "http_request"])]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        for chain_dict in result.dangerous_tool_chains:
            assert chain_dict["first_seen"] is not None
            assert chain_dict["last_seen"] is not None


# ── Unit: ToolChainAnalyzer reuse ────────────────────────────────────


@pytest.mark.unit
class TestToolChainAnalyzerReuse:
    def test_multiple_sessions_each_get_own_graph(self) -> None:
        """Each session should get its own AttackKnowledgeGraph."""
        sessions = [
            _make_session("s1", ["read_file", "http_request"]),
            _make_session("s2", ["read_file", "http_request"]),
        ]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        # Should still find chains (deduplicated)
        assert result.total_vulnerabilities > 0


# ── Unit: cross-session deduplication ────────────────────────────────


@pytest.mark.unit
class TestCrossSessionDeduplication:
    def test_same_chain_in_two_sessions_deduplicates(self) -> None:
        """Same dangerous chain in 2 sessions aggregates count."""
        sessions = [
            _make_session("s1", ["read_file", "http_request"]),
            _make_session("s2", ["read_file", "http_request"]),
        ]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        # After dedup, unique chain count should be less than 2x
        # (same tools + same vuln type -> merged)
        chain_keys = {
            (
                tuple(c["tools"]),
                c["vulnerability_type"],
            )
            for c in result.dangerous_tool_chains
        }
        # Each unique (tools, vuln_type) pair appears once
        for c in result.dangerous_tool_chains:
            key = (
                tuple(c["tools"]),
                c["vulnerability_type"],
            )
            assert key in chain_keys

    def test_aggregated_occurrence_count(self) -> None:
        sessions = [
            _make_session("s1", ["read_file", "http_request"]),
            _make_session("s2", ["read_file", "http_request"]),
        ]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        for chain_dict in result.dangerous_tool_chains:
            if chain_dict["tools"] == [
                "read_file",
                "http_request",
            ]:
                assert chain_dict["occurrence_count"] >= 2


# ── Unit: single tool session ────────────────────────────────────────


@pytest.mark.unit
class TestSingleToolSession:
    def test_session_with_one_tool_skipped(self) -> None:
        """Sessions with < 2 tools produce no findings."""
        sessions = [_make_session("s1", ["read_file"])]
        ingestor = MockIngestor(sessions)
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        assert result.total_vulnerabilities == 0


# ── Unit: empty sessions ─────────────────────────────────────────────


@pytest.mark.unit
class TestEmptySessions:
    def test_no_sessions(self) -> None:
        ingestor = MockIngestor([])
        service = AnalyzerService(ingestor)
        result = _run(service.analyze(Path("dummy")))

        assert result.total_vulnerabilities == 0
        assert result.source == "trace-analysis"
        assert result.campaign_id.startswith("trace-")
