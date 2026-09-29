"""OpenTelemetry JSONL trace ingestor.

Parses OTLP-JSON exported traces (one ResourceSpans batch per line)
and reconstructs :class:`TraceSession` objects grouped by ``session.id``
(span attribute, then resource attribute), else ``traceId``.
"""

from __future__ import annotations

import contextlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.domain.ports.trace_ingestor import TraceIngestor
from ziran.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)


def _nano_to_datetime(nano_str: str) -> datetime:
    """Convert a nanosecond epoch string to a UTC datetime."""
    nanos = int(nano_str)
    seconds = nanos / 1_000_000_000
    return datetime.fromtimestamp(seconds, tz=UTC)


def _get_attribute(attributes: list[dict[str, Any]], key: str) -> str | None:
    """Extract a string attribute value from OTel attribute list."""
    for attr in attributes:
        if attr.get("key") == key:
            value = attr.get("value", {})
            return str(
                value.get("stringValue") or value.get("intValue") or value.get("boolValue", "")
            )
    return None


class OTelIngestor(TraceIngestor):
    """Ingest OpenTelemetry JSONL trace exports.

    Each line in the JSONL file is a ``ResourceSpans`` batch following
    the OTLP JSON format.  Spans are grouped by ``session.id`` (span
    attribute, then resource attribute), else ``traceId``, into
    :class:`TraceSession` objects.
    """

    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]:
        """Parse a JSONL file and return reconstructed sessions.

        Args:
            source: Path to a ``.jsonl`` file with one ResourceSpans
                    JSON object per line.

        Returns:
            List of :class:`TraceSession` grouped by session key.

        Raises:
            FileNotFoundError: If *source* does not exist.
            ValueError: If the file has content but no valid JSON line.
        """
        path = Path(source)
        if not path.exists():
            msg = f"OTel trace file not found: {path}"
            raise FileNotFoundError(msg)

        # Collect spans grouped by session key
        traces: dict[str, list[dict[str, Any]]] = defaultdict(list)
        agent_names: dict[str, str] = {}
        seen = parsed = 0

        with path.open() as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                seen += 1
                try:
                    batch = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("skipping_malformed_json", line=line_no)
                    continue

                parsed += 1
                self._process_batch(batch, traces, agent_names)

        if seen and not parsed:
            msg = f"No valid OTLP JSON lines in trace file: {path}"
            raise ValueError(msg)

        # Build TraceSession per session key
        sessions: list[TraceSession] = []
        for trace_id, spans in traces.items():
            session = self._build_session(trace_id, spans, agent_names.get(trace_id, "unknown"))
            if session is not None:
                sessions.append(session)

        logger.info(
            "otel_sessions_parsed",
            session_count=len(sessions),
            path=str(path),
        )
        return sessions

    def _process_batch(
        self,
        batch: dict[str, Any],
        traces: dict[str, list[dict[str, Any]]],
        agent_names: dict[str, str],
    ) -> None:
        """Extract spans from a ResourceSpans batch."""
        for resource_span in batch.get("resourceSpans", []):
            resource = resource_span.get("resource", {})
            resource_attrs = resource.get("attributes", [])
            service_name = _get_attribute(resource_attrs, "service.name") or "unknown"
            resource_session = _get_attribute(resource_attrs, "session.id")

            for scope_span in resource_span.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    key = (
                        _get_attribute(span.get("attributes", []), "session.id")
                        or resource_session
                        or span.get("traceId", "")
                    )
                    if not key:
                        continue
                    traces[key].append(span)
                    agent_names.setdefault(key, service_name)

    def _build_session(
        self,
        trace_id: str,
        spans: list[dict[str, Any]],
        agent_name: str,
    ) -> TraceSession | None:
        """Build a TraceSession from a list of spans."""
        tool_calls: list[ToolCallEvent] = []

        for span in spans:
            attributes = span.get("attributes", [])
            tool_name = _get_attribute(attributes, "gen_ai.tool.name")
            if not tool_name:
                continue

            start_nano = span.get("startTimeUnixNano", "0")
            timestamp = _nano_to_datetime(start_nano)

            # Parse arguments if available
            args_str = _get_attribute(attributes, "gen_ai.tool.arguments")
            arguments: dict[str, Any] = {}
            if args_str:
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    arguments = json.loads(args_str)

            tool_calls.append(
                ToolCallEvent(
                    tool_name=tool_name,
                    arguments=arguments,
                    timestamp=timestamp,
                    span_id=span.get("spanId"),
                    parent_span_id=span.get("parentSpanId"),
                )
            )

        if not tool_calls:
            return None

        # Sort by timestamp
        tool_calls.sort(key=lambda tc: tc.timestamp)

        start_time = tool_calls[0].timestamp
        end_time = tool_calls[-1].timestamp

        # Use span end times if available
        for span in spans:
            end_nano = span.get("endTimeUnixNano", "0")
            if end_nano and end_nano != "0":
                span_end = _nano_to_datetime(end_nano)
                if span_end > end_time:
                    end_time = span_end

        return TraceSession(
            session_id=trace_id,
            agent_name=agent_name,
            tool_calls=tool_calls,
            start_time=start_time,
            end_time=end_time,
            source="otel",
        )
