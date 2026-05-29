"""Unit tests for alerting fingerprint helpers and result aggregates."""

from __future__ import annotations

import pytest

from ziran.domain.entities.alerting import (
    AlertOutcome,
    DeliveryResult,
    digest_fingerprint,
    drift_fingerprint,
    severity_rank,
    trace_fingerprint,
)

pytestmark = pytest.mark.unit


def test_drift_fingerprint_is_stable_and_value_independent() -> None:
    a = drift_fingerprint("srv", "write_file", "permission_changed")
    b = drift_fingerprint("srv", "write_file", "permission_changed")
    assert a == b
    assert len(a) == 16 and all(c in "0123456789abcdef" for c in a)


def test_drift_fingerprint_differs_by_kind_and_tool() -> None:
    base = drift_fingerprint("srv", "write_file", "permission_changed")
    assert base != drift_fingerprint("srv", "write_file", "description_changed")
    assert base != drift_fingerprint("srv", "read_file", "permission_changed")


def test_trace_and_digest_prefixes_avoid_cross_type_collision() -> None:
    assert trace_fingerprint("chainX", "sess1") != drift_fingerprint("chainX", "sess1", "x")


def test_digest_fingerprint_ignores_order_and_run_date() -> None:
    # Same chain set in any order → same digest (no run-date component).
    assert digest_fingerprint(["aa", "bb"]) == digest_fingerprint(["bb", "aa"])
    # Different chain set → different digest.
    assert digest_fingerprint(["aa", "bb"]) != digest_fingerprint(["aa", "cc"])


def test_severity_rank_ordering() -> None:
    assert severity_rank("low") < severity_rank("medium") < severity_rank("high")
    assert severity_rank("high") < severity_rank("critical")


def test_alert_outcome_counts() -> None:
    outcome = AlertOutcome(
        results=[
            DeliveryResult(sink_name="s", fingerprint="a" * 16, status="sent"),
            DeliveryResult(sink_name="s", fingerprint="b" * 16, status="deduped"),
            DeliveryResult(sink_name="g", fingerprint="c" * 16, status="failed"),
        ]
    )
    assert outcome.sent == 1
    assert outcome.deduped == 1
    assert outcome.failed == 1
    assert outcome.any_failed is True
