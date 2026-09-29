"""Tests for the OTel JSONL trace ingestor."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ziran.infrastructure.trace_ingestors.otel_ingestor import (
    OTelIngestor,
    _get_attribute,
    _nano_to_datetime,
)

if TYPE_CHECKING:
    from ziran.domain.entities.trace import TraceSession

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


# ── Unit: session.id grouping (#421) ─────────────────────────────────


def _span_line(
    tool: str,
    start: int,
    *,
    trace_id: str | None = "a" * 32,
    session_id: str | None = None,
    resource_session_id: str | None = None,
) -> str:
    """Build one OTLP-JSON ResourceSpans line with a single tool span."""
    attrs = [{"key": "gen_ai.tool.name", "value": {"stringValue": tool}}]
    if session_id is not None:
        attrs.append({"key": "session.id", "value": {"stringValue": session_id}})
    resource_attrs = [{"key": "service.name", "value": {"stringValue": "claude-code"}}]
    if resource_session_id is not None:
        resource_attrs.append({"key": "session.id", "value": {"stringValue": resource_session_id}})
    span: dict[str, object] = {
        "spanId": f"{start:016x}",
        "name": tool,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(start),
        "attributes": attrs,
    }
    if trace_id is not None:
        span["traceId"] = trace_id
    batch = {
        "resourceSpans": [
            {"resource": {"attributes": resource_attrs}, "scopeSpans": [{"spans": [span]}]}
        ]
    }
    return json.dumps(batch)


def _ingest_lines(ingestor: OTelIngestor, tmp_path: Path, lines: list[str]) -> list[TraceSession]:
    path = tmp_path / "traces.jsonl"
    path.write_text("\n".join(lines) + "\n")
    result: list[TraceSession] = _run(ingestor.ingest(path))
    return result


@pytest.mark.unit
class TestOTelSessionIdGrouping:
    def test_session_id_groups_across_trace_ids(
        self, ingestor: OTelIngestor, tmp_path: Path
    ) -> None:
        sessions = _ingest_lines(
            ingestor,
            tmp_path,
            [
                _span_line("WebFetch", 2_000, trace_id="b" * 32, session_id="s1"),
                _span_line("Read", 1_000, trace_id="a" * 32, session_id="s1"),
            ],
        )
        assert len(sessions) == 1
        assert sessions[0].session_id == "s1"
        assert [c.tool_name for c in sessions[0].tool_calls] == ["Read", "WebFetch"]

    def test_shared_trace_id_split_by_session_id(
        self, ingestor: OTelIngestor, tmp_path: Path
    ) -> None:
        sessions = _ingest_lines(
            ingestor,
            tmp_path,
            [
                _span_line("Read", 1_000, session_id="s1"),
                _span_line("WebFetch", 2_000, session_id="s2"),
            ],
        )
        assert sorted(s.session_id for s in sessions) == ["s1", "s2"]

    def test_resource_session_id_used(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        sessions = _ingest_lines(
            ingestor, tmp_path, [_span_line("Read", 1_000, resource_session_id="r1")]
        )
        assert [s.session_id for s in sessions] == ["r1"]

    def test_span_session_id_wins_over_resource(
        self, ingestor: OTelIngestor, tmp_path: Path
    ) -> None:
        sessions = _ingest_lines(
            ingestor,
            tmp_path,
            [_span_line("Read", 1_000, session_id="span", resource_session_id="res")],
        )
        assert [s.session_id for s in sessions] == ["span"]

    def test_session_id_without_trace_id_kept(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        sessions = _ingest_lines(
            ingestor,
            tmp_path,
            [
                _span_line("Read", 1_000, trace_id=None, session_id="s1"),
                _span_line("Grep", 2_000, trace_id=None),
            ],
        )
        assert [s.session_id for s in sessions] == ["s1"]
        assert len(sessions[0].tool_calls) == 1

    def test_trace_id_fallback(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        sessions = _ingest_lines(ingestor, tmp_path, [_span_line("Read", 1_000)])
        assert [s.session_id for s in sessions] == ["a" * 32]

    def test_all_lines_invalid_raises(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        path = tmp_path / "garbage.jsonl"
        path.write_text("not json\nalso not json\n")
        with pytest.raises(ValueError, match="No valid OTLP JSON"):
            _run(ingestor.ingest(path))

    def test_empty_file_returns_empty(self, ingestor: OTelIngestor, tmp_path: Path) -> None:
        path = tmp_path / "empty.jsonl"
        path.write_text("\n")
        assert _run(ingestor.ingest(path)) == []
