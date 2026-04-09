"""Langfuse trace ingestor.

Supports two modes:

1. **File mode** -- reads a JSON file containing a list of Langfuse
   trace objects (or a single trace object).
2. **API mode** -- uses the ``langfuse`` SDK to fetch traces from the
   Langfuse API (requires ``pip install ziran[langfuse]``).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.domain.ports.trace_ingestor import TraceIngestor

logger = logging.getLogger(__name__)


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO 8601 datetime string to a UTC datetime."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class LangfuseIngestor(TraceIngestor):
    """Ingest traces from Langfuse (file or API).

    File mode expects a JSON array of trace objects, each containing
    an ``observations`` list with ``SPAN`` and ``GENERATION`` entries.
    Only ``SPAN`` observations are treated as tool calls.
    """

    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]:
        """Ingest traces from file or API.

        Args:
            source: Path to a JSON file, or ``"api"`` to use the
                    Langfuse SDK.
            **kwargs: Passed to ``_ingest_api`` when source is
                      ``"api"`` (e.g. ``project_id``, ``since``).

        Returns:
            List of :class:`TraceSession` objects.
        """
        if str(source) == "api":
            return await self._ingest_api(**kwargs)
        return await self._ingest_file(Path(source))

    async def _ingest_file(self, path: Path) -> list[TraceSession]:
        """Parse a Langfuse JSON export file."""
        if not path.exists():
            msg = f"Langfuse trace file not found: {path}"
            raise FileNotFoundError(msg)

        raw = json.loads(path.read_text())

        # Normalize to a list
        traces: list[dict[str, Any]]
        if isinstance(raw, list):
            traces = raw
        elif isinstance(raw, dict):
            traces = [raw]
        else:
            msg = "Expected a JSON array or object"
            raise ValueError(msg)

        sessions: list[TraceSession] = []
        for trace_data in traces:
            session = self._parse_trace(trace_data)
            if session is not None:
                sessions.append(session)

        logger.info(
            "Langfuse ingestor: parsed %d sessions from %s",
            len(sessions),
            path,
        )
        return sessions

    async def _ingest_api(self, **kwargs: Any) -> list[TraceSession]:
        """Fetch traces from the Langfuse API using the SDK."""
        try:
            from langfuse import Langfuse
        except ImportError:
            msg = "Langfuse SDK not installed. Run: pip install ziran[langfuse]"
            raise ImportError(msg) from None

        client = Langfuse()
        fetch_kwargs: dict[str, Any] = {}
        if "limit" in kwargs:
            fetch_kwargs["limit"] = kwargs["limit"]

        response = client.fetch_traces(**fetch_kwargs)
        traces_data = response.data if hasattr(response, "data") else []

        sessions: list[TraceSession] = []
        for trace_obj in traces_data:
            trace_dict = trace_obj.dict() if hasattr(trace_obj, "dict") else trace_obj
            session = self._parse_trace(trace_dict)
            if session is not None:
                sessions.append(session)

        logger.info(
            "Langfuse API ingestor: fetched %d sessions",
            len(sessions),
        )
        return sessions

    def _parse_trace(self, trace_data: dict[str, Any]) -> TraceSession | None:
        """Parse a single Langfuse trace into a TraceSession."""
        trace_id = trace_data.get("id", "")
        session_id = trace_data.get("sessionId") or trace_id
        observations = trace_data.get("observations", [])

        tool_calls: list[ToolCallEvent] = []
        for obs in observations:
            obs_type = obs.get("type", "")
            if obs_type != "SPAN":
                continue

            tool_name = obs.get("name", "")
            if not tool_name:
                continue

            start_str = obs.get("startTime", "")
            if not start_str:
                continue

            timestamp = _parse_iso_datetime(start_str)

            arguments: dict[str, Any] = {}
            input_data = obs.get("input")
            if isinstance(input_data, dict):
                arguments = input_data

            result = obs.get("output")

            tool_calls.append(
                ToolCallEvent(
                    tool_name=tool_name,
                    arguments=arguments,
                    result=result,
                    timestamp=timestamp,
                    span_id=obs.get("id"),
                )
            )

        if not tool_calls:
            return None

        tool_calls.sort(key=lambda tc: tc.timestamp)

        # Determine session time bounds
        start_str = trace_data.get("startTime", "")
        end_str = trace_data.get("endTime", "")

        start_time = _parse_iso_datetime(start_str) if start_str else tool_calls[0].timestamp
        end_time = _parse_iso_datetime(end_str) if end_str else tool_calls[-1].timestamp

        metadata = trace_data.get("metadata", {})
        agent_name = "unknown"
        if isinstance(metadata, dict):
            agent_name = metadata.get("agent", "unknown")

        return TraceSession(
            session_id=session_id,
            agent_name=agent_name,
            tool_calls=tool_calls,
            start_time=start_time,
            end_time=end_time,
            source="langfuse",
            metadata=metadata if isinstance(metadata, dict) else {},
        )
