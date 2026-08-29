"""Tests for the OpenTelemetry metrics module.

Covers the no-op fallback (unconfigured), exporter wiring via mocks, and
that each recording helper writes to the right instrument with the right
labels using an in-memory metric reader.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from ziran.infrastructure.telemetry import metrics

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def captured() -> Iterator[InMemoryMetricReader]:
    """Wire ``metrics._METRICS`` to an in-memory reader and tear down after."""
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    metrics._METRICS = metrics._Instruments(provider.get_meter("ziran"))
    try:
        yield reader
    finally:
        metrics._METRICS = None
        provider.shutdown()


def _points(reader: InMemoryMetricReader) -> dict[str, list[dict[str, Any]]]:
    """Return ``{metric_name: [attribute dicts]}`` from a scrape."""
    out: dict[str, list[dict[str, Any]]] = {}
    data = reader.get_metrics_data()
    if data is None:
        return out
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                out[metric.name] = [dict(dp.attributes) for dp in metric.data.data_points]
    return out


# ── No-op path ────────────────────────────────────────────────────────


class TestNoOp:
    def test_helpers_noop_when_unconfigured(self) -> None:
        """Every helper must be a silent no-op when metrics are not configured."""
        metrics._METRICS = None
        metrics.campaign_started("c1", "standard")
        metrics.campaign_completed("c1", "standard")
        metrics.attack_started("recon")
        metrics.record_attack(
            phase="recon",
            vector_id="v1",
            provider="mock",
            coverage_level="standard",
            successful=True,
            refused=False,
            duration_seconds=0.1,
        )
        metrics.record_phase(
            phase="recon", coverage_level="standard", duration_seconds=1.0, tokens=10
        )

    def test_configure_noop_without_flags(self) -> None:
        """configure_metrics with no endpoint/port leaves metrics unconfigured."""
        metrics._METRICS = None
        metrics.configure_metrics()
        assert metrics._METRICS is None

    def test_get_meter_returns_none_without_otel(self) -> None:
        with patch("ziran.infrastructure.telemetry.metrics._HAS_OTEL", False):
            assert metrics.get_meter("x") is None

    def test_get_meter_returns_meter_with_otel(self) -> None:
        # OTel SDK is installed in the test env -> a real meter is returned.
        assert metrics.get_meter("ziran.test") is not None

    def test_finish_span_none_is_noop(self) -> None:
        """finish_campaign_span with a None span must not raise."""
        from ziran.application.agent_scanner import campaign_telemetry

        campaign_telemetry.finish_campaign_span(
            None,
            campaign_id="c1",
            coverage_level="standard",
            total_vulnerabilities=0,
            trust_score=0.5,
            duration_seconds=1.0,
            total_tokens=0,
            dangerous_chain_count=0,
        )


# ── configure_metrics wiring ──────────────────────────────────────────


class TestConfigure:
    def test_pull_wires_prometheus_reader(self) -> None:
        prom_reader = MagicMock()
        start_server = MagicMock()
        with (
            patch.dict(
                "sys.modules",
                {
                    "opentelemetry.exporter.prometheus": MagicMock(
                        PrometheusMetricReader=MagicMock(return_value=prom_reader)
                    ),
                    "prometheus_client": MagicMock(start_http_server=start_server),
                },
            ),
        ):
            try:
                metrics.configure_metrics(port=19999)
                start_server.assert_called_once_with(19999)
                assert metrics._METRICS is not None
            finally:
                metrics.reset_metrics()

    def test_push_wires_otlp_reader(self) -> None:
        exporter_cls = MagicMock()
        periodic_cls = MagicMock()
        with (
            patch.dict(
                "sys.modules",
                {
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter": MagicMock(
                        OTLPMetricExporter=exporter_cls
                    ),
                    "opentelemetry.sdk.metrics.export": MagicMock(
                        PeriodicExportingMetricReader=periodic_cls
                    ),
                },
            ),
        ):
            try:
                metrics.configure_metrics(endpoint="http://collector:4318")
                exporter_cls.assert_called_once_with(endpoint="http://collector:4318")
                assert metrics._METRICS is not None
            finally:
                metrics.reset_metrics()

    def test_configure_noop_without_otel(self) -> None:
        with patch("ziran.infrastructure.telemetry.metrics._HAS_OTEL", False):
            metrics.configure_metrics(port=1234)
            assert metrics._METRICS is None


# ── Recording onto real instruments ───────────────────────────────────


class TestRecording:
    def test_campaign_counters(self, captured: InMemoryMetricReader) -> None:
        metrics.campaign_started("c1", "standard")
        metrics.campaign_completed("c1", "standard")
        pts = _points(captured)
        assert pts["ziran.campaigns.started"][0] == {
            "campaign_id": "c1",
            "coverage_level": "standard",
        }
        assert "ziran.campaigns.completed" in pts

    def test_attack_counters_and_labels(self, captured: InMemoryMetricReader) -> None:
        metrics.attack_started("recon")
        metrics.record_attack(
            phase="recon",
            vector_id="pi_001",
            provider="mock",
            coverage_level="standard",
            successful=True,
            refused=False,
            duration_seconds=0.25,
        )
        pts = _points(captured)
        expected = {
            "phase": "recon",
            "vector_id": "pi_001",
            "provider": "mock",
            "coverage_level": "standard",
        }
        assert pts["ziran.attacks.executed"][0] == expected
        assert pts["ziran.attacks.succeeded"][0] == expected
        assert "ziran.attacks.refused" not in pts  # not refused
        assert pts["ziran.attack.duration_seconds"][0] == expected

    def test_refused_counter(self, captured: InMemoryMetricReader) -> None:
        metrics.record_attack(
            phase="exec",
            vector_id="pi_002",
            provider="mock",
            coverage_level="quick",
            successful=False,
            refused=True,
            duration_seconds=0.1,
        )
        pts = _points(captured)
        assert pts["ziran.attacks.refused"][0]["vector_id"] == "pi_002"
        assert "ziran.attacks.succeeded" not in pts

    def test_phase_metrics_have_no_vector_id(self, captured: InMemoryMetricReader) -> None:
        metrics.record_phase(
            phase="recon", coverage_level="standard", duration_seconds=2.0, tokens=42
        )
        pts = _points(captured)
        phase_labels = pts["ziran.phase.duration_seconds"][0]
        assert phase_labels == {"phase": "recon", "coverage_level": "standard"}
        assert "vector_id" not in phase_labels
        assert pts["ziran.campaign.tokens_per_phase"][0] == {
            "phase": "recon",
            "coverage_level": "standard",
        }

    def test_active_concurrent_gauge(self, captured: InMemoryMetricReader) -> None:
        metrics.attack_started("recon")
        metrics.attack_started("recon")
        pts = _points(captured)
        gauge = pts["ziran.phase.active_concurrent"][0]
        assert gauge == {"phase": "recon"}
        assert "vector_id" not in gauge

    def test_started_finished_balance_gauge(self, captured: InMemoryMetricReader) -> None:
        metrics.attack_started("recon")
        metrics.attack_started("recon")
        metrics.attack_finished("recon")
        pts = _points(captured)
        # Gauge reports the latest value (2 up, 1 down -> 1).
        assert pts["ziran.phase.active_concurrent"][0] == {"phase": "recon"}
        assert metrics._METRICS is not None
        assert metrics._METRICS.inflight["recon"] == 1


# ── Campaign wiring (scanner -> phase -> attack instrumentation) ───────


@pytest.mark.asyncio
class TestCampaignInstrumentation:
    async def test_campaign_records_all_levels(
        self, captured: InMemoryMetricReader, mock_adapter: Any
    ) -> None:
        from ziran.application.agent_scanner.scanner import AgentScanner
        from ziran.domain.entities.phase import CoverageLevel, ScanPhase

        scanner = AgentScanner(adapter=mock_adapter)
        await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            coverage=CoverageLevel.ESSENTIAL,
        )
        pts = _points(captured)
        assert "ziran.campaigns.started" in pts
        assert "ziran.campaigns.completed" in pts
        assert "ziran.attacks.executed" in pts
        assert "ziran.phase.duration_seconds" in pts
        # provider label derives from the adapter class name (MockAgentAdapter)
        assert pts["ziran.attacks.executed"][0]["provider"] == "mockagent"
        assert pts["ziran.attacks.executed"][0]["phase"] == "reconnaissance"

    async def test_attack_timeout_balances_concurrency(
        self, captured: InMemoryMetricReader
    ) -> None:
        """A timed-out attack still balances the active-concurrent gauge."""
        from types import SimpleNamespace

        from ziran.application.agent_scanner.phase_executor import PhaseExecutor
        from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
        from ziran.domain.entities.phase import CoverageLevel, ScanPhase

        attack = SimpleNamespace(id="v1", name="V1")

        class _SlowExecutor:
            provider = "mockagent"

            async def execute(self, _attack: Any) -> Any:
                raise TimeoutError

        class _Library:
            def get_attacks_for_phase(self, _phase: Any, coverage: Any) -> list[Any]:
                return [attack]

        pe = PhaseExecutor(
            _SlowExecutor(),  # type: ignore[arg-type]
            _Library(),  # type: ignore[arg-type]
            AttackKnowledgeGraph(),
            attack_timeout=0.01,
        )
        await pe.execute(
            ScanPhase.RECONNAISSANCE,
            0,
            1,
            coverage=CoverageLevel.ESSENTIAL,
            tested_vector_ids=set(),
            attack_results=[],
        )
        # attack_started then attack_finished (in finally) -> gauge back to 0.
        assert metrics._METRICS is not None
        assert metrics._METRICS.inflight["reconnaissance"] == 0


# ── CLI wiring ────────────────────────────────────────────────────────


class TestCli:
    def test_metrics_flags_in_scan_help(self) -> None:
        from click.testing import CliRunner

        from ziran.interfaces.cli.main import cli

        result = CliRunner().invoke(cli, ["scan", "--help"])
        assert "--metrics-endpoint" in result.output
        assert "--metrics-port" in result.output

    def test_scan_wires_configure_metrics(self) -> None:
        from click.testing import CliRunner

        from ziran.interfaces.cli.main import cli

        with patch("ziran.infrastructure.telemetry.metrics.configure_metrics") as configure:
            # No target given -> validation exits after metrics are configured.
            CliRunner().invoke(cli, ["scan", "--metrics-port", "9464"])
            configure.assert_called_once_with(endpoint=None, port=9464)

    def test_scan_wires_push_endpoint(self) -> None:
        from click.testing import CliRunner

        from ziran.interfaces.cli.main import cli

        with patch("ziran.infrastructure.telemetry.metrics.configure_metrics") as configure:
            CliRunner().invoke(cli, ["scan", "--metrics-endpoint", "http://collector:4318"])
            configure.assert_called_once_with(endpoint="http://collector:4318", port=None)
