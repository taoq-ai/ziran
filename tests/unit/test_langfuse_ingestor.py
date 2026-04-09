"""Tests for the Langfuse trace ingestor."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ziran.infrastructure.trace_ingestors.langfuse_ingestor import (
    LangfuseIngestor,
    _parse_iso_datetime,
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

    def test_api_mode_without_sdk(self, ingestor: LangfuseIngestor) -> None:
        """API mode raises ImportError if langfuse not installed."""
        import builtins

        _real_import = builtins.__import__

        def _block_langfuse(name: str, *args: object, **kwargs: object) -> object:
            if name == "langfuse":
                raise ImportError("mocked: no langfuse")
            return _real_import(name, *args, **kwargs)

        with (
            patch("builtins.__import__", side_effect=_block_langfuse),
            pytest.raises(ImportError, match="Langfuse SDK"),
        ):
            _run(ingestor.ingest("api"))
