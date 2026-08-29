"""OpenTelemetry metrics with zero-overhead no-op fallback.

Mirrors :mod:`ziran.infrastructure.telemetry.tracing`. Instrumented code
calls the ``record_*`` helpers unconditionally; until :func:`configure_metrics`
wires an exporter (and only when the OTel SDK is installed) every call
short-circuits on a single ``is None`` check, so the core install carries no
metrics overhead.

Instruments (Prometheus names shown after OTel dot-to-underscore mapping)::

    ziran.campaigns.started      -> ziran_campaigns_started_total   (counter)
    ziran.campaigns.completed    -> ziran_campaigns_completed_total (counter)
    ziran.attacks.executed       -> ziran_attacks_executed_total    (counter)
    ziran.attacks.succeeded      -> ziran_attacks_succeeded_total   (counter)
    ziran.attacks.refused        -> ziran_attacks_refused_total     (counter)
    ziran.campaign.tokens_per_phase -> ..._tokens_per_phase         (gauge)
    ziran.phase.active_concurrent   -> ..._active_concurrent        (gauge)
    ziran.attack.duration_seconds   -> ..._duration_seconds         (histogram)
    ziran.phase.duration_seconds    -> ..._duration_seconds         (histogram)

Example::

    from ziran.infrastructure.telemetry import metrics

    metrics.configure_metrics(port=9464)  # Prometheus pull endpoint
    metrics.campaign_started("campaign_1", "standard")
"""

from __future__ import annotations

from typing import Any

try:
    from opentelemetry import metrics as _otel_metrics

    _HAS_OTEL = True
except ImportError:  # pragma: no cover - exercised via mock
    _HAS_OTEL = False
    _otel_metrics = None  # type: ignore[assignment,unused-ignore]


class _Instruments:
    """Holds the concrete OTel instruments, created once from a meter."""

    def __init__(self, meter: Any) -> None:
        self.campaigns_started = meter.create_counter(
            "ziran.campaigns.started", description="Campaigns started"
        )
        self.campaigns_completed = meter.create_counter(
            "ziran.campaigns.completed", description="Campaigns completed"
        )
        self.attacks_executed = meter.create_counter(
            "ziran.attacks.executed", description="Attack vectors executed"
        )
        self.attacks_succeeded = meter.create_counter(
            "ziran.attacks.succeeded", description="Attack vectors that succeeded"
        )
        self.attacks_refused = meter.create_counter(
            "ziran.attacks.refused", description="Attack vectors the agent refused"
        )
        self.tokens_per_phase = meter.create_gauge(
            "ziran.campaign.tokens_per_phase", description="Tokens consumed in the last phase"
        )
        self.phase_active_concurrent = meter.create_gauge(
            "ziran.phase.active_concurrent", description="Attacks running concurrently in a phase"
        )
        self.attack_duration = meter.create_histogram(
            "ziran.attack.duration_seconds", unit="s", description="Wall-clock duration per attack"
        )
        self.phase_duration = meter.create_histogram(
            "ziran.phase.duration_seconds", unit="s", description="Wall-clock duration per phase"
        )
        # Live count of in-flight attacks per phase, backing the concurrency gauge.
        self.inflight: dict[str, int] = {}


# Module global: ``None`` until configure_metrics wires an exporter.
_METRICS: _Instruments | None = None
_PROVIDER: Any = None


def get_meter(name: str) -> Any:
    """Return an OTel meter or a no-op fallback (parallels ``get_tracer``)."""
    if _HAS_OTEL and _otel_metrics is not None:
        return _otel_metrics.get_meter(name)
    return None


def configure_metrics(*, endpoint: str | None = None, port: int | None = None) -> None:
    """Wire a Prometheus pull reader and/or an OTLP push reader.

    Args:
        endpoint: OTLP/HTTP collector URL for the periodic push exporter.
        port: TCP port for the Prometheus pull (``/metrics``) scrape endpoint.

    Does nothing when the OTel SDK is not installed, or when neither
    ``endpoint`` nor ``port`` is provided.
    """
    global _METRICS, _PROVIDER

    if not _HAS_OTEL or (endpoint is None and port is None):
        return

    from opentelemetry.sdk.metrics import MeterProvider

    readers: list[Any] = []

    if port is not None:
        from opentelemetry.exporter.prometheus import PrometheusMetricReader
        from prometheus_client import start_http_server

        start_http_server(port)
        readers.append(PrometheusMetricReader())

    if endpoint is not None:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        readers.append(PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint)))

    _PROVIDER = MeterProvider(metric_readers=readers)
    # Read the meter directly from our provider — set_meter_provider only wins
    # the first call process-wide, so we never depend on it succeeding.
    _METRICS = _Instruments(_PROVIDER.get_meter("ziran"))


def reset_metrics() -> None:
    """Tear down configured metrics (test teardown / reconfigure)."""
    global _METRICS, _PROVIDER
    if _PROVIDER is not None:
        try:
            _PROVIDER.shutdown()
        except Exception:  # pragma: no cover - best-effort teardown
            pass
    _METRICS = None
    _PROVIDER = None


# ── Recording helpers (no-op when metrics unconfigured) ───────────────────


def campaign_started(campaign_id: str, coverage_level: str) -> None:
    """Increment the campaigns-started counter."""
    if _METRICS is None:
        return
    _METRICS.campaigns_started.add(
        1, {"campaign_id": campaign_id, "coverage_level": coverage_level}
    )


def campaign_completed(campaign_id: str, coverage_level: str) -> None:
    """Increment the campaigns-completed counter."""
    if _METRICS is None:
        return
    _METRICS.campaigns_completed.add(
        1, {"campaign_id": campaign_id, "coverage_level": coverage_level}
    )


def attack_started(phase: str) -> None:
    """Record an attack entering execution (bumps the concurrency gauge)."""
    if _METRICS is None:
        return
    _METRICS.inflight[phase] = _METRICS.inflight.get(phase, 0) + 1
    _METRICS.phase_active_concurrent.set(_METRICS.inflight[phase], {"phase": phase})


def attack_finished(phase: str) -> None:
    """Record an attack leaving execution (drops the concurrency gauge).

    Paired with :func:`attack_started` in a ``finally`` so the gauge stays
    balanced even when an attack times out or errors.
    """
    if _METRICS is None:
        return
    remaining = max(_METRICS.inflight.get(phase, 1) - 1, 0)
    _METRICS.inflight[phase] = remaining
    _METRICS.phase_active_concurrent.set(remaining, {"phase": phase})


def record_attack(
    *,
    phase: str,
    vector_id: str,
    provider: str,
    coverage_level: str,
    successful: bool,
    refused: bool,
    duration_seconds: float,
) -> None:
    """Record counters + duration histogram for a finished attack."""
    if _METRICS is None:
        return
    labels = {
        "phase": phase,
        "vector_id": vector_id,
        "provider": provider,
        "coverage_level": coverage_level,
    }
    _METRICS.attacks_executed.add(1, labels)
    if successful:
        _METRICS.attacks_succeeded.add(1, labels)
    if refused:
        _METRICS.attacks_refused.add(1, labels)
    _METRICS.attack_duration.record(duration_seconds, labels)


def record_phase(
    *,
    phase: str,
    coverage_level: str,
    duration_seconds: float,
    tokens: int,
) -> None:
    """Record per-phase duration histogram and tokens-per-phase gauge."""
    if _METRICS is None:
        return
    labels = {"phase": phase, "coverage_level": coverage_level}
    _METRICS.phase_duration.record(duration_seconds, labels)
    _METRICS.tokens_per_phase.set(tokens, labels)
