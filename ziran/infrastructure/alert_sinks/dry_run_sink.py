"""Dry-run wrapper: prints the intended payload without any network I/O."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ziran.domain.entities.alerting import DeliveryResult
from ziran.domain.ports.alert_sink import AlertSink

if TYPE_CHECKING:
    from ziran.domain.entities.alerting import AlertableFinding


class DryRunSink(AlertSink):
    """Wraps a real sink; logs what *would* be sent and performs no I/O."""

    def __init__(self, inner: AlertSink) -> None:
        self._inner = inner
        self.name = inner.name

    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        payload = {
            "sink": self._inner.name,
            "fingerprint": finding.fingerprint,
            "severity": finding.severity,
            "title": finding.title,
            "fields": finding.fields,
            "links": [link.model_dump() for link in finding.links],
        }
        print(f"[dry-run-alerts] would send -> {json.dumps(payload, default=str)}")
        return DeliveryResult(
            sink_name=self._inner.name,
            fingerprint=finding.fingerprint,
            status="dry_run",
            detail="payload preview printed",
        )
