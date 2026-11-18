"""Tests for the Langfuse trace ingestor."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ziran.infrastructure.trace_ingestors.langfuse_ingestor import (
    LangfuseIngestor,
    _parse_iso_datetime,
    _parse_since,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
LANGFUSE_FIXTURE = FIXTURES_DIR / "sample_langfuse_traces.json"


@pytest.fixture
def ingestor() -> LangfuseIngestor:
    return LangfuseIngestor()


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


# ── Unit: datetime parsing ───────────────────────────────────────────


@pytest.mark.unit
class TestIsoDatetimeParsing:
    def test_parses_z_suffix(self) -> None:
        dt = _parse_iso_datetime("2023-11-14T22:13:20Z")
        assert dt.year == 2023
        assert dt.month == 11
        assert dt.day == 14

    def test_parses_offset(self) -> None:
        dt = _parse_iso_datetime("2023-11-14T14:13:20-08:00")
        assert dt.year == 2023


# ── Unit: observation parsing ────────────────────────────────────────


@pytest.mark.unit
class TestLangfuseObservationParsing:
    def test_filters_span_type_only(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        # trace-001 has 3 observations but only 2 are SPAN
        assert len(trace_001.tool_calls) == 2

    def test_ignores_generation_type(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        tool_names = [tc.tool_name for tc in trace_001.tool_calls]
        assert "llm-call" not in tool_names


# ── Unit: session grouping ───────────────────────────────────────────


@pytest.mark.unit
class TestLangfuseSessionGrouping:
    def test_groups_by_session_id(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        session_ids = {s.session_id for s in sessions}
        assert "session-alpha" in session_ids
        assert "session-beta" in session_ids
        assert "session-gamma" in session_ids

    def test_session_count(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        assert len(sessions) == 4


# ── Unit: tool call extraction ───────────────────────────────────────


@pytest.mark.unit
class TestLangfuseToolCallExtraction:
    def test_extracts_tool_names(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        tool_names = [tc.tool_name for tc in trace_001.tool_calls]
        assert tool_names == ["read_file", "http_request"]

    def test_extracts_input_as_arguments(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        assert trace_001.tool_calls[0].arguments == {"path": "/etc/passwd"}

    def test_extracts_output_as_result(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        assert trace_001.tool_calls[0].result == "root:x:0:0:root:/root:/bin/bash"


# ── Unit: timestamp ordering ────────────────────────────────────────


@pytest.mark.unit
class TestLangfuseTimestampOrdering:
    def test_tool_calls_sorted_by_time(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        for session in sessions:
            timestamps = [tc.timestamp for tc in session.tool_calls]
            assert timestamps == sorted(timestamps)


# ── Unit: source metadata ───────────────────────────────────────────


@pytest.mark.unit
class TestLangfuseSourceMetadata:
    def test_source_is_langfuse(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        for session in sessions:
            assert session.source == "langfuse"

    def test_agent_name_from_metadata(self, ingestor: LangfuseIngestor) -> None:
        sessions = _run(ingestor.ingest(LANGFUSE_FIXTURE))
        trace_001 = next(s for s in sessions if s.session_id == "session-alpha")
        assert trace_001.agent_name == "agent-alpha"


# ── Unit: error handling ─────────────────────────────────────────────


@pytest.mark.unit
class TestLangfuseErrorHandling:
    def test_file_not_found(self, ingestor: LangfuseIngestor) -> None:
        with pytest.raises(FileNotFoundError):
            _run(ingestor.ingest(Path("/nonexistent/file.json")))

    def test_single_trace_object(self, ingestor: LangfuseIngestor, tmp_path: Path) -> None:
        """A single trace dict (not array) should be accepted."""
        single = {
            "id": "single-trace",
            "startTime": "2023-11-14T22:13:20Z",
            "endTime": "2023-11-14T22:13:23Z",
            "observations": [
                {
                    "id": "obs-1",
                    "type": "SPAN",
                    "name": "search",
                    "startTime": "2023-11-14T22:13:20Z",
                }
            ],
        }
        path = tmp_path / "single.json"
        path.write_text(json.dumps(single))
        sessions = _run(ingestor.ingest(path))
        assert len(sessions) == 1
        assert sessions[0].session_id == "single-trace"

    def test_tool_observations_are_tool_calls(
        self, ingestor: LangfuseIngestor, tmp_path: Path
    ) -> None:
        trace = {
            "id": "t-tool",
            "observations": [
                {
                    "id": "o1",
                    "type": "TOOL",
                    "name": "read_file",
                    "startTime": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "o2",
                    "type": "TOOL",
                    "name": "http_request",
                    "startTime": "2026-01-01T00:00:01Z",
                },
                {"id": "o3", "type": "EVENT", "name": "note", "startTime": "2026-01-01T00:00:02Z"},
            ],
        }
        path = tmp_path / "tool.json"
        path.write_text(json.dumps([trace]))
        sessions = _run(ingestor.ingest(path))
        assert [c.tool_name for c in sessions[0].tool_calls] == ["read_file", "http_request"]

    def test_string_input_decoded_to_arguments(self, ingestor: LangfuseIngestor) -> None:
        obs = {"id": "o", "type": "SPAN", "name": "bash", "startTime": "2026-01-01T00:00:00Z"}
        cases = ['{"command": "ls"}', "plain text", "[1, 2]"]
        parsed = [
            ingestor._parse_trace({"id": "t", "observations": [{**obs, "input": raw}]})
            for raw in cases
        ]
        assert [p.tool_calls[0].arguments for p in parsed if p] == [{"command": "ls"}, {}, {}]

    def test_deeply_nested_input_does_not_abort(self, ingestor: LangfuseIngestor) -> None:
        """A nested-array bomb raises RecursionError in json.loads; the call keeps no arguments."""
        obs = {"id": "o", "type": "SPAN", "name": "bash", "startTime": "2026-01-01T00:00:00Z"}
        bomb = "[" * 200_000 + "]" * 200_000
        session = ingestor._parse_trace({"id": "t", "observations": [{**obs, "input": bomb}]})
        assert session is not None
        assert session.tool_calls[0].arguments == {}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "delta"),
    [("24h", timedelta(hours=24)), ("7d", timedelta(days=7)), (" 30m ", timedelta(minutes=30))],
)
def test_parse_since_relative(value: str, delta: timedelta) -> None:
    before = datetime.now(UTC)
    got = _parse_since(value)
    assert abs((before - delta) - got) < timedelta(seconds=5)


@pytest.mark.unit
def test_parse_since_iso_and_errors() -> None:
    assert _parse_since("2026-01-02") == datetime(2026, 1, 2, tzinfo=UTC)
    assert _parse_since("2026-01-02T03:04:05+02:00") == datetime(2026, 1, 2, 1, 4, 5, tzinfo=UTC)
    for bad in ["", "yesterday", "24x", "-1h"]:
        with pytest.raises(ValueError, match="--since"):
            _parse_since(bad)
