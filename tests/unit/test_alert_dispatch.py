"""Unit tests for the alert dispatcher: floor filtering, fan-out, aggregation."""

from __future__ import annotations

import pytest

from tests.fixtures.alerting import make_finding
from ziran.application.alerting.dispatch import dispatch
from ziran.domain.entities.alerting import AlertableFinding, DeliveryResult
from ziran.domain.ports.alert_sink import AlertSink

pytestmark = pytest.mark.unit


class RecordingSink(AlertSink):
    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self._fail = fail
        self.emitted: list[str] = []

    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        self.emitted.append(finding.fingerprint)
        status = "failed" if self._fail else "sent"
        return DeliveryResult(sink_name=self.name, fingerprint=finding.fingerprint, status=status)


async def test_below_floor_is_skipped_without_emit() -> None:
    sink = RecordingSink("slack")
    finding = make_finding(severity="low")
    outcome = await dispatch([finding], [(sink, "high")])
    assert sink.emitted == []  # never called
    assert outcome.results[0].status == "skipped_below_floor"


async def test_at_or_above_floor_is_emitted() -> None:
    sink = RecordingSink("slack")
    finding = make_finding(severity="high")
    outcome = await dispatch([finding], [(sink, "high")])
    assert sink.emitted == [finding.fingerprint]
    assert outcome.sent == 1


async def test_one_sink_failure_does_not_block_others() -> None:
    good = RecordingSink("slack")
    bad = RecordingSink("github_issue", fail=True)
    finding = make_finding(severity="critical")
    outcome = await dispatch([finding], [(bad, "low"), (good, "low")])
    assert good.emitted == [finding.fingerprint]  # still delivered
    assert outcome.failed == 1
    assert outcome.sent == 1
    assert outcome.any_failed is True
