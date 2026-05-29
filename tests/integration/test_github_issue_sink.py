"""Integration test: GitHub issue sink create + marker-search dedup (respx)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest
import respx

from tests.fixtures.alerting import make_finding
from ziran.infrastructure.alert_sinks.github_issue_sink import GitHubIssueSink

pytestmark = pytest.mark.integration

REPO = "myorg/ai-agent-infra"
SEARCH = "https://api.github.com/search/issues"
CREATE = f"https://api.github.com/repos/{REPO}/issues"


def _stateful_github(created: list[dict[str, Any]]) -> None:
    """Wire respx routes that emulate GitHub's search + create with dedup."""

    def search_handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        hit = next((i for i in created if i["fingerprint"] in q), None)
        items = [{"html_url": hit["html_url"]}] if hit else []
        return httpx.Response(200, json={"total_count": len(items), "items": items})

    def create_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.read().decode())
        # Recover the embedded fingerprint marker to register the new issue.
        match = re.search(r"ziran-fingerprint:\s*([0-9a-f]{16})", payload["body"])
        fp = match.group(1) if match else ""
        num = len(created) + 1
        url = f"https://github.com/{REPO}/issues/{num}"
        created.append({"fingerprint": fp, "html_url": url})
        return httpx.Response(201, json={"html_url": url, "number": num})

    respx.get(SEARCH).mock(side_effect=search_handler)
    respx.post(CREATE).mock(side_effect=create_handler)


@respx.mock
async def test_create_then_dedup_on_rerun() -> None:
    created: list[dict[str, Any]] = []
    _stateful_github(created)
    sink = GitHubIssueSink(repo=REPO, token="tok", labels=["mcp-drift"])
    finding = make_finding()

    first = await sink.emit(finding)
    assert first.status == "sent"
    assert first.detail and first.detail.endswith("/issues/1")
    assert len(created) == 1

    # Re-run on the same finding: search finds the marker → no new POST.
    second = await sink.emit(finding)
    assert second.status == "deduped"
    assert second.detail == first.detail
    assert len(created) == 1  # zero duplicate issues


@respx.mock
async def test_missing_token_fails_cleanly() -> None:
    sink = GitHubIssueSink(repo=REPO, token=None)
    result = await sink.emit(make_finding())
    assert result.status == "failed"
    assert "token" in (result.detail or "").lower()


@respx.mock
async def test_create_sends_labels_and_marker() -> None:
    created: list[dict[str, Any]] = []
    _stateful_github(created)
    route = respx.post(CREATE)
    sink = GitHubIssueSink(repo=REPO, token="tok", labels=["mcp-drift", "security"])

    await sink.emit(make_finding(fingerprint="0123456789abcdef"))

    body = route.calls.last.request.read().decode()
    assert "ziran-fingerprint: 0123456789abcdef" in body
    assert "mcp-drift" in body
