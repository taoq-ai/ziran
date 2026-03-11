"""Tests for OpenTelemetry tracing module.

Covers the no-op fallback path (always available) and mocked OTel
tracer path to ensure instrumented code emits correct span attributes.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ziran.infrastructure.telemetry.tracing import (
    NoOpSpan,
    NoOpTracer,
    get_tracer,
)

# ── NoOpSpan tests ────────────────────────────────────────────────────


class TestNoOpSpan:
    def test_set_attribute(self) -> None:
        span = NoOpSpan()
        span.set_attribute("key", "value")  # should not raise

    def test_set_attributes(self) -> None:
        span = NoOpSpan()
        span.set_attributes({"a": 1, "b": "two"})

    def test_add_event(self) -> None:
        span = NoOpSpan()
        span.add_event("test_event", {"detail": "info"})

    def test_set_status(self) -> None:
        span = NoOpSpan()
        span.set_status("OK")

    def test_record_exception(self) -> None:
        span = NoOpSpan()
        span.record_exception(ValueError("test"))

    def test_end(self) -> None:
        span = NoOpSpan()
        span.end()

    def test_context_manager(self) -> None:
        span = NoOpSpan()
        with span as s:
            assert s is span
            s.set_attribute("inside", True)


# ── NoOpTracer tests ──────────────────────────────────────────────────


class TestNoOpTracer:
    def test_start_as_current_span(self) -> None:
        tracer = NoOpTracer()
        with tracer.start_as_current_span("test.span") as span:
            assert isinstance(span, NoOpSpan)
            span.set_attribute("key", "value")

    def test_start_span(self) -> None:
        tracer = NoOpTracer()
        span = tracer.start_span("test.span")
        assert isinstance(span, NoOpSpan)
        span.end()


# ── get_tracer() tests ────────────────────────────────────────────────


class TestGetTracer:
    def test_returns_noop_when_otel_not_installed(self) -> None:
        """Without OTel, get_tracer should return NoOpTracer."""
        with patch("ziran.infrastructure.telemetry.tracing._HAS_OTEL", False):
            tracer = get_tracer("test.module")
            assert isinstance(tracer, NoOpTracer)

    def test_returns_real_tracer_when_otel_installed(self) -> None:
        """With OTel, get_tracer should delegate to trace.get_tracer."""
        mock_trace = MagicMock()
        mock_tracer = MagicMock()
        mock_trace.get_tracer.return_value = mock_tracer

        with (
            patch("ziran.infrastructure.telemetry.tracing._HAS_OTEL", True),
            patch("ziran.infrastructure.telemetry.tracing._otel_trace", mock_trace),
        ):
            tracer = get_tracer("test.module")
            assert tracer is mock_tracer
            mock_trace.get_tracer.assert_called_once_with("test.module")


# ── Instrumented module integration ──────────────────────────────────


class TestScannerTracing:
    """Verify scanner creates spans via no-op tracer (no OTel installed)."""

    def test_scanner_imports_tracer(self) -> None:
        """Scanner module should import get_tracer without errors."""
        from ziran.application.agent_scanner import scanner

        assert hasattr(scanner, "_tracer")

    def test_pipeline_imports_tracer(self) -> None:
        """Pipeline module should import get_tracer without errors."""
        from ziran.application.detectors import pipeline

        assert hasattr(pipeline, "_tracer")

    def test_chain_analyzer_imports_tracer(self) -> None:
        """Chain analyzer module should import get_tracer without errors."""
        from ziran.application.knowledge_graph import chain_analyzer

        assert hasattr(chain_analyzer, "_tracer")


# ── configure_console_exporter tests ─────────────────────────────────


class TestConfigureConsoleExporter:
    def test_noop_without_otel(self) -> None:
        """Should do nothing when OTel is not installed."""
        from ziran.infrastructure.telemetry.tracing import configure_console_exporter

        with patch("ziran.infrastructure.telemetry.tracing._HAS_OTEL", False):
            configure_console_exporter()  # should not raise

    def test_configures_provider_with_otel(self) -> None:
        """Should configure TracerProvider when OTel SDK is available."""
        from ziran.infrastructure.telemetry.tracing import configure_console_exporter

        mock_trace = MagicMock()
        mock_provider_cls = MagicMock()
        mock_exporter_cls = MagicMock()
        mock_processor_cls = MagicMock()

        with (
            patch("ziran.infrastructure.telemetry.tracing._HAS_OTEL", True),
            patch("ziran.infrastructure.telemetry.tracing._otel_trace", mock_trace),
            patch.dict(
                "sys.modules",
                {
                    "opentelemetry.sdk.trace": MagicMock(TracerProvider=mock_provider_cls),
                    "opentelemetry.sdk.trace.export": MagicMock(
                        BatchSpanProcessor=mock_processor_cls,
                        ConsoleSpanExporter=mock_exporter_cls,
                    ),
                },
            ),
        ):
            configure_console_exporter()
            mock_trace.set_tracer_provider.assert_called_once()
