"""Alert dispatch: severity-floor filtering + concurrent fan-out + aggregation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ziran.domain.entities.alerting import (
    AlertableFinding,
    AlertOutcome,
    DeliveryResult,
    severity_rank,
)

if TYPE_CHECKING:
    from ziran.domain.entities.attack import Severity
    from ziran.domain.ports.alert_sink import AlertSink

# (sink, severity_floor) — the floor is applied by the dispatcher, not the sink.
SinkBinding = tuple["AlertSink", "Severity"]


async def _emit_one(sink: AlertSink, floor: Severity, finding: AlertableFinding) -> DeliveryResult:
    if severity_rank(finding.severity) < severity_rank(floor):
        return DeliveryResult(
            sink_name=sink.name,
            fingerprint=finding.fingerprint,
            status="skipped_below_floor",
        )
    return await sink.emit(finding)


async def dispatch(
    findings: list[AlertableFinding],
    sinks: list[SinkBinding],
) -> AlertOutcome:
    """Deliver every finding to every sink at/above its severity floor.

    Sinks never raise per the :class:`AlertSink` contract, so a single failure
    is captured as a failed :class:`DeliveryResult` and never blocks the rest.
    """
    tasks = [_emit_one(sink, floor, finding) for finding in findings for sink, floor in sinks]
    results = await asyncio.gather(*tasks)
    return AlertOutcome(results=list(results))
