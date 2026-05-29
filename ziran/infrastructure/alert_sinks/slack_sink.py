"""Slack webhook alert sink (Block Kit + text fallback)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from ziran.domain.entities.alerting import DeliveryResult
from ziran.domain.ports.alert_sink import AlertSink

if TYPE_CHECKING:
    from ziran.domain.entities.alerting import AlertableFinding

_SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_diamond:",
    "low": ":white_circle:",
}


class SlackWebhookSink(AlertSink):
    """Posts a Block Kit message per finding to a Slack incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str, timeout: float = 15.0) -> None:
        self._webhook_url = webhook_url
        self._timeout = timeout

    def _build_payload(self, finding: AlertableFinding) -> dict[str, Any]:
        emoji = _SEVERITY_EMOJI.get(finding.severity, "")
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {finding.title}"[:150]},
            }
        ]
        if finding.fields:
            blocks.append(
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*{k}:*\n{v}"}
                        for k, v in finding.fields.items()
                    ][:10],
                }
            )
        if finding.links:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"<{link.url}|{link.label}>"}
                        for link in finding.links
                    ],
                }
            )
        return {
            "text": f"{emoji} [{finding.kind}] {finding.summary}",
            "blocks": blocks,
        }

    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._webhook_url, json=self._build_payload(finding))
            if resp.status_code == httpx.codes.OK:
                return DeliveryResult(
                    sink_name=self.name, fingerprint=finding.fingerprint, status="sent"
                )
            return DeliveryResult(
                sink_name=self.name,
                fingerprint=finding.fingerprint,
                status="failed",
                detail=f"slack responded {resp.status_code}: {resp.text[:200]}",
            )
        except httpx.HTTPError as exc:
            return DeliveryResult(
                sink_name=self.name,
                fingerprint=finding.fingerprint,
                status="failed",
                detail=f"slack request error: {exc}",
            )
