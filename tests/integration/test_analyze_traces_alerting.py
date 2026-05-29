"""Integration test: analyze-traces alerting end-to-end + dedup (respx)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from ziran.application.trace_analysis.analyzer_service import AnalyzerService
from ziran.domain.entities.alerting import AlertConfig, AlertSinkConfig
from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.domain.ports.trace_ingestor import TraceIngestor
from ziran.infrastructure.alert_sinks.factory import build_sinks

pytestmark = pytest.mark.integration

REPO = "myorg/ai-agent-infra"
SEARCH = "https://api.github.com/search/issues"
CREATE = f"https://api.github.com/repos/{REPO}/issues"


class _Ingestor(TraceIngestor):
    def __init__(self, sessions: list[TraceSession]) -> None:
        self._sessions = sessions

    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]:
        return self._sessions


def _session(session_id: str, tools: list[str]) -> TraceSession:
    ts = datetime(2026, 5, 29, 12, 0, 0, tzinfo=UTC)
    return TraceSession(
        session_id=session_id,
        tool_calls=[
            ToolCallEvent(tool_name=t, timestamp=datetime(2026, 5, 29, 12, 0, i, tzinfo=UTC))
            for i, t in enumerate(tools)
        ],
        start_time=ts,
        end_time=ts,
        source="otel",
    )


def _wire_github(created: list[dict[str, Any]]) -> None:
    def search_handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        hit = next((i for i in created if i["fingerprint"] in q), None)
        items = [{"html_url": hit["html_url"]}] if hit else []
        return httpx.Response(200, json={"total_count": len(items), "items": items})

    def create_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.read().decode())
        match = re.search(r"ziran-fingerprint:\s*([0-9a-f]{16})", payload["body"])
        fp = match.group(1) if match else ""
        num = len(created) + 1
        url = f"https://github.com/{REPO}/issues/{num}"
        created.append({"fingerprint": fp, "html_url": url})
        return httpx.Response(201, json={"html_url": url, "number": num})

    respx.get(SEARCH).mock(side_effect=search_handler)
    respx.post(CREATE).mock(side_effect=create_handler)


def _github_sinks() -> list[Any]:
    config = AlertConfig(alerts=[AlertSinkConfig(kind="github_issue", repo=REPO, token="tok")])
    return build_sinks(config)


@respx.mock
async def test_dangerous_chain_files_one_issue_then_dedups() -> None:
    created: list[dict[str, Any]] = []
    _wire_github(created)
    service = AnalyzerService(_Ingestor([_session("sess-1", ["read_file", "http_request"])]))

    outcome = await service.emit_findings(Path("dummy"), _github_sinks())
    assert outcome.sent == 1
    assert len(created) == 1

    # Re-run on the same trace → dedup, zero new issues.
    outcome2 = await service.emit_findings(Path("dummy"), _github_sinks())
    assert outcome2.deduped == 1
    assert len(created) == 1


@respx.mock
async def test_digest_mode_files_single_issue_for_multiple_sessions() -> None:
    created: list[dict[str, Any]] = []
    _wire_github(created)
    service = AnalyzerService(
        _Ingestor(
            [
                _session("sess-1", ["read_file", "http_request"]),
                _session("sess-2", ["read_file", "http_request"]),
            ]
        )
    )

    outcome = await service.emit_findings(Path("dummy"), _github_sinks(), digest=True)

    assert outcome.sent == 1  # one aggregated digest issue
    assert len(created) == 1


@respx.mock
async def test_issue_body_contains_tool_sequence_and_session() -> None:
    created: list[dict[str, Any]] = []
    _wire_github(created)
    route = respx.post(CREATE)
    service = AnalyzerService(_Ingestor([_session("sess-xyz", ["read_file", "http_request"])]))

    await service.emit_findings(Path("dummy"), _github_sinks())

    body = json.loads(route.calls.last.request.read().decode())["body"]
    assert "read_file → http_request" in body
    assert "sess-xyz" in body
