"""Integration test: watch-registry alerting end-to-end + dedup (respx)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest
import respx

from ziran.application.registry_watch.watcher_service import emit_findings
from ziran.domain.entities.alerting import AlertConfig, AlertSinkConfig
from ziran.domain.entities.registry import DriftFinding
from ziran.infrastructure.alert_sinks.factory import build_sinks

pytestmark = pytest.mark.integration

REPO = "myorg/ai-agent-infra"
SEARCH = "https://api.github.com/search/issues"
CREATE = f"https://api.github.com/repos/{REPO}/issues"
WEBHOOK = "https://hooks.slack.test/abc"


def _drift() -> list[DriftFinding]:
    return [
        DriftFinding(
            server_name="prod-mcp-server",
            drift_type="permission_changed",
            severity="high",
            tool_name="write_file",
            field="permissions",
            previous_value="[]",
            current_value="['fs:write']",
            message="permissions changed",
        ),
        DriftFinding(
            server_name="prod-mcp-server",
            drift_type="tool_added",
            severity="medium",
            tool_name="exec_shell",
            current_value="run a shell command",
            message="new tool added",
        ),
    ]


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


@respx.mock
async def test_drift_reaches_both_sinks_then_dedups_on_rerun() -> None:
    created: list[dict[str, Any]] = []
    _wire_github(created)
    slack = respx.post(WEBHOOK).mock(return_value=httpx.Response(200, text="ok"))

    config = AlertConfig(
        alerts=[
            AlertSinkConfig(kind="slack", webhook_url=WEBHOOK, severity_floor="low"),
            AlertSinkConfig(kind="github_issue", repo=REPO, token="tok", labels=["mcp-drift"]),
        ]
    )
    sinks = build_sinks(config)
    findings = _drift()

    outcome = await emit_findings(findings, sinks)
    assert outcome.sent == 4  # 2 findings x 2 sinks
    assert slack.call_count == 2
    assert len(created) == 2

    # Re-run: GitHub dedups (no new issues), Slack re-posts (stateless).
    outcome2 = await emit_findings(findings, sinks)
    assert outcome2.deduped == 2  # both GitHub issues deduped
    assert len(created) == 2  # zero new issues


@respx.mock
async def test_severity_floor_filters_github_sink() -> None:
    created: list[dict[str, Any]] = []
    _wire_github(created)
    config = AlertConfig(
        alerts=[AlertSinkConfig(kind="github_issue", repo=REPO, token="tok", severity_floor="high")]
    )
    sinks = build_sinks(config)

    outcome = await emit_findings(_drift(), sinks)

    # Only the 'high' permission_changed finding clears the floor; 'medium' is skipped.
    assert outcome.sent == 1
    assert sum(1 for r in outcome.results if r.status == "skipped_below_floor") == 1
    assert len(created) == 1


@respx.mock
async def test_dry_run_contacts_no_services() -> None:
    config = AlertConfig(
        alerts=[
            AlertSinkConfig(kind="slack", webhook_url=WEBHOOK),
            AlertSinkConfig(kind="github_issue", repo=REPO, token="tok"),
        ]
    )
    sinks = build_sinks(config, dry_run=True)

    outcome = await emit_findings(_drift(), sinks)

    assert all(r.status == "dry_run" for r in outcome.results)
    assert not respx.calls  # zero network I/O
