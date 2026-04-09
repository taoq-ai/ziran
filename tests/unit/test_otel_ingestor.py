"""Tests for the OTel JSONL trace ingestor."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ziran.infrastructure.trace_ingestors.otel_ingestor import (
    OTelIngestor,
    _get_attribute,
    _nano_to_datetime,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
OTEL_FIXTURE = FIXTURES_DIR / "sample_otel_traces.jsonl"


# ── Helpers ──────────────────────────────────────────────────────────


@pytest.fixture
def ingestor() -> OTelIngestor:
    return OTelIngestor()


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


# ── Unit: nano_to_datetime ───────────────────────────────────────────


@pytest.mark.unit
class TestNanoToDatetime:
    def test_converts_epoch_nanos(self) -> None:
        dt = _nano_to_datetime("1700000000000000000")
        assert dt.year == 2023
        assert dt.month == 11

    def test_zero_returns_epoch(self) -> None:
        dt = _nano_to_datetime("0")
        assert dt.year == 1970


# ── Unit: get_attribute ──────────────────────────────────────────────


@pytest.mark.unit
class TestGetAttribute:
    def test_finds_string_value(self) -> None:
        attrs = [{"key": "service.name", "value": {"stringValue": "my-svc"}}]
        assert _get_attribute(attrs, "service.name") == "my-svc"

    def test_returns_none_for_missing(self) -> None:
        attrs = [{"key": "other.key", "value": {"stringValue": "val"}}]
        assert _get_attribute(attrs, "service.name") is None

    def test_empty_list(self) -> None:
        assert _get_attribute([], "any.key") is None


# ── Unit: session grouping ───────────────────────────────────────────


@pytest.mark.unit
class TestOTelIngestorSessionGrouping:
    def test_groups_by_trace_id(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        session_ids = {s.session_id for s in sessions}
        # Expect 4 traces: trace-001, trace-002, trace-003a, trace-003b
        assert "trace-001" in session_ids
        assert "trace-002" in session_ids
        assert "trace-003a" in session_ids
        assert "trace-003b" in session_ids

    def test_session_count(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        assert len(sessions) == 4


# ── Unit: tool call extraction ───────────────────────────────────────


@pytest.mark.unit
class TestOTelToolCallExtraction:
    def test_extracts_tool_names(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "trace-001")
        tool_names = [tc.tool_name for tc in trace_001.tool_calls]
        assert tool_names == ["read_file", "http_request"]

    def test_extracts_arguments(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "trace-001")
        assert trace_001.tool_calls[0].arguments == {"path": "/etc/passwd"}

    def test_span_ids_present(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "trace-001")
        assert trace_001.tool_calls[0].span_id == "span-001a"
        assert trace_001.tool_calls[1].parent_span_id == "span-001a"


# ── Unit: timestamp ordering ────────────────────────────────────────


@pytest.mark.unit
class TestOTelTimestampOrdering:
    def test_tool_calls_sorted_by_time(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        for session in sessions:
            timestamps = [tc.timestamp for tc in session.tool_calls]
            assert timestamps == sorted(timestamps)

    def test_session_times_correct(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "trace-001")
        assert trace_001.start_time < trace_001.end_time


# ── Unit: agent name extraction ──────────────────────────────────────


@pytest.mark.unit
class TestOTelAgentName:
    def test_extracts_service_name(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "trace-001")
        assert trace_001.agent_name == "agent-alpha"

    def test_source_is_otel(self, ingestor: OTelIngestor) -> None:
        sessions = _run(ingestor.ingest(OTEL_FIXTURE))
        for session in sessions:
            assert session.source == "otel"


# ── Unit: error handling ─────────────────────────────────────────────


@pytest.mark.unit
class TestOTelErrorHandling:
    def test_file_not_found(self, ingestor: OTelIngestor) -> None:
        with pytest.raises(FileNotFoundError):
            _run(ingestor.ingest(Path("/nonexistent/file.jsonl")))

    def test_malformed_lines_skipped(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.jsonl"
        bad_file.write_text("not valid json\n{}\n")
        sessions = _run(ingestor.ingest(bad_file))
        assert sessions == []
