"""Integration test: Slack webhook sink request shape (respx-mocked)."""

from __future__ import annotations

import httpx
import pytest
import respx

from tests.fixtures.alerting import make_finding
from ziran.infrastructure.alert_sinks.slack_sink import SlackWebhookSink

pytestmark = pytest.mark.integration

WEBHOOK = "https://hooks.slack.test/services/T/B/xxx"


@respx.mock
async def test_slack_sink_posts_block_kit_payload() -> None:
    route = respx.post(WEBHOOK).mock(return_value=httpx.Response(200, text="ok"))
    sink = SlackWebhookSink(webhook_url=WEBHOOK)

    result = await sink.emit(make_finding(severity="critical"))

    assert result.status == "sent"
    assert route.called
    body = route.calls.last.request.read().decode()
    assert '"blocks"' in body
    assert "rotating_light" in body  # critical emoji
    assert "prod-mcp-server" in body


@respx.mock
async def test_slack_sink_reports_failure_on_non_200() -> None:
    respx.post(WEBHOOK).mock(return_value=httpx.Response(500, text="boom"))
    sink = SlackWebhookSink(webhook_url=WEBHOOK)

    result = await sink.emit(make_finding())

    assert result.status == "failed"
    assert "500" in (result.detail or "")
