"""Langfuse trace ingestor.

Supports two modes:

1. **File mode** -- reads a JSON file containing a list of Langfuse
   trace objects (or a single trace object).
2. **API mode** -- pulls observations live from the Langfuse public API
   (``GET /api/public/v2/observations``, basic auth from ``LANGFUSE_PUBLIC_KEY``
   and ``LANGFUSE_SECRET_KEY``) with ``httpx``, and groups them by trace.
   Reference: https://cloud.langfuse.com/generated/api/openapi.yml
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.domain.ports.trace_ingestor import TraceIngestor
from ziran.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

DEFAULT_HOST = "https://cloud.langfuse.com"
_TOOL_TYPES = frozenset({"SPAN", "TOOL"})
_MAX_RETRIES = 3
_MAX_RETRY_WAIT = 60.0
_PAGE_LIMIT = 100
_SINCE_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO 8601 datetime string to a UTC datetime."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _parse_since(value: str) -> datetime:
    """Parse ``--since``: ``<n>m``, ``<n>h``, ``<n>d`` (before now) or an ISO 8601 date."""
    text = value.strip()
    match = re.fullmatch(r"(\d+)([mhd])", text)
    if match:
        return datetime.now(UTC) - timedelta(**{_SINCE_UNITS[match[2]]: int(match[1])})
    try:
        return _parse_iso_datetime(text).astimezone(UTC)
    except ValueError:
        msg = f"Invalid --since {value!r}: use e.g. 24h, 7d or an ISO date (2026-01-31)."
        raise ValueError(msg) from None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


class LangfuseIngestor(TraceIngestor):
    """Ingest traces from Langfuse (file or API).

    File mode expects a JSON array of trace objects, each containing
    an ``observations`` list with ``SPAN`` and ``GENERATION`` entries.
    ``SPAN`` and ``TOOL`` observations are treated as tool calls.
    """

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._pending_cursor: tuple[Path, dict[str, Any]] | None = None

    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]:
        """Ingest traces from file or API.

        Args:
            source: Path to a JSON file, or ``"api"`` to pull from the
                    Langfuse public API.
            **kwargs: Passed to ``_ingest_api`` when source is ``"api"``
                      (``since``, ``session_id``, ``project_id``, ``incremental``).

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
            "langfuse_sessions_parsed",
            session_count=len(sessions),
            path=path,
        )
        return sessions

    async def _ingest_api(
        self,
        since: str = "24h",
        session_id: str | None = None,
        project_id: str | None = None,
        incremental: bool = False,
    ) -> list[TraceSession]:
        """Pull observations from the Langfuse public API and parse them per trace."""
        public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
        secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
        if not public_key or not secret_key:
            msg = "Langfuse API mode needs LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY set."
            raise ValueError(msg)
        host = os.environ.get("LANGFUSE_HOST") or DEFAULT_HOST

        start = _parse_since(since)
        cache_path = self._cache_path(host, public_key)
        seen: set[str] = set()
        if incremental and cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                start = _parse_iso_datetime(cached["last_start_time"])
                seen = set(cached.get("ids_at_last", []))
            except (ValueError, KeyError, TypeError) as exc:
                msg = (
                    f"Unreadable incremental cursor {cache_path}: delete it to restart at --since."
                )
                raise ValueError(msg) from exc

        params: dict[str, Any] = {
            "fields": "core,basic,io",
            "limit": _PAGE_LIMIT,
            "fromStartTime": _iso(start),
        }
        if session_id:
            params["sessionId"] = session_id

        observations: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            base_url=host,
            auth=(public_key, secret_key),
            timeout=30.0,
            transport=self._transport,
        ) as client:
            while True:
                body = await self._get_page(client, params)
                observations.extend(body.get("data", []))
                cursor = body.get("meta", {}).get("cursor")
                if not cursor:
                    break
                params["cursor"] = cursor

        # fromStartTime is inclusive: skip what the last run already analysed at its cursor.
        observations = [
            o
            for o in observations
            if o.get("id") not in seen and (not project_id or o.get("projectId") == project_id)
        ]

        if incremental and observations:
            newest = max(_parse_iso_datetime(o["startTime"]) for o in observations)
            ids = [o["id"] for o in observations if _parse_iso_datetime(o["startTime"]) == newest]
            if newest == start:
                ids += sorted(seen)
            self._pending_cursor = (
                cache_path,
                {"last_start_time": _iso(newest), "ids_at_last": ids},
            )

        traces: dict[str, dict[str, Any]] = {}
        for obs in observations:
            trace_id = obs.get("traceId") or obs.get("id", "")
            trace = traces.setdefault(
                trace_id, {"id": trace_id, "sessionId": obs.get("sessionId"), "observations": []}
            )
            trace["observations"].append(obs)

        sessions = [s for t in traces.values() if (s := self._parse_trace(t)) is not None]
        logger.info(
            "langfuse_api_sessions_fetched",
            observation_count=len(observations),
            session_count=len(sessions),
        )
        return sessions

    async def _get_page(self, client: httpx.AsyncClient, params: dict[str, Any]) -> dict[str, Any]:
        """GET one page, waiting out a 429 up to ``_MAX_RETRIES`` times."""
        for attempt in range(_MAX_RETRIES + 1):
            response = await client.get("/api/public/v2/observations", params=params)
            if response.status_code != 429:
                response.raise_for_status()
                body: dict[str, Any] = response.json()
                return body
            if attempt == _MAX_RETRIES:
                break
            try:
                wait = float(response.headers.get("Retry-After", "1"))
            except ValueError:
                wait = 1.0
            await asyncio.sleep(min(max(wait, 0.0), _MAX_RETRY_WAIT))
        msg = f"Langfuse rate limit: still HTTP 429 after {_MAX_RETRIES} retries."
        raise RuntimeError(msg)

    @staticmethod
    def _cache_path(host: str, public_key: str) -> Path:
        digest = hashlib.sha256(f"{host}\n{public_key}".encode()).hexdigest()[:12]
        return Path(".ziran") / "trace_cache" / f"langfuse-{digest}.json"

    def save_cursor(self) -> None:
        """Persist the incremental cursor of the last pull (no key is written)."""
        if self._pending_cursor is None:
            return
        path, data = self._pending_cursor
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, path)
        self._pending_cursor = None

    def _parse_trace(self, trace_data: dict[str, Any]) -> TraceSession | None:
        """Parse a single Langfuse trace into a TraceSession."""
        trace_id = trace_data.get("id", "")
        session_id = trace_data.get("sessionId") or trace_id
        observations = trace_data.get("observations", [])

        tool_calls: list[ToolCallEvent] = []
        for obs in observations:
            obs_type = obs.get("type", "")
            if obs_type not in _TOOL_TYPES:
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
            if isinstance(input_data, str):  # the v2 API returns input as a raw string
                try:
                    input_data = json.loads(input_data)
                except ValueError:
                    input_data = None
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
