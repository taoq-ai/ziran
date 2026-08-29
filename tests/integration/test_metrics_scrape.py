"""Integration test — live Prometheus pull endpoint (mock scrape).

Configures the metrics module with a real Prometheus reader on a free
port, records a few instruments, then acts as Prometheus and scrapes
``/metrics``, asserting the ZIRAN metric families and labels appear in the
exposition text.
"""

from __future__ import annotations

import socket

import httpx
import pytest

pytest.importorskip("opentelemetry.metrics", reason="opentelemetry-sdk not installed")
pytest.importorskip("opentelemetry.exporter.prometheus", reason="prometheus exporter not installed")

from ziran.infrastructure.telemetry import metrics

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_prometheus_scrape_exposes_metrics() -> None:
    port = _free_port()
    metrics.configure_metrics(port=port)
    try:
        # Record across all three instrument kinds.
        metrics.campaign_started("campaign_1", "standard")
        metrics.attack_started("reconnaissance")
        metrics.record_attack(
            phase="reconnaissance",
            vector_id="pi_001",
            provider="mockagent",
            coverage_level="standard",
            successful=True,
            refused=False,
            duration_seconds=0.42,
        )
        metrics.record_phase(
            phase="reconnaissance",
            coverage_level="standard",
            duration_seconds=1.5,
            tokens=123,
        )

        body = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=5.0).text

        # Counter (Prometheus appends _total), histogram, and gauge families.
        assert "ziran_campaigns_started_total" in body
        assert "ziran_attacks_executed_total" in body
        assert "ziran_attacks_succeeded_total" in body
        assert "ziran_attack_duration_seconds" in body
        assert "ziran_phase_duration_seconds" in body
        assert "ziran_campaign_tokens_per_phase" in body
        # Labels present and vector_id scoped to attack-level series.
        assert 'vector_id="pi_001"' in body
        assert 'provider="mockagent"' in body
        assert 'coverage_level="standard"' in body
    finally:
        metrics.reset_metrics()
