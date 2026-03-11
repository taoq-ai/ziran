"""OpenTelemetry tracing with zero-overhead no-op fallback.

When ``opentelemetry-api`` is installed the module returns real OTel
tracers and spans. Without the package a lightweight no-op
implementation is used so instrumented code never needs conditional
imports.

Example::

    from ziran.infrastructure.telemetry.tracing import get_tracer

    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("ziran.campaign") as span:
        span.set_attribute("campaign_id", "abc123")
        span.add_event("vulnerability_found", {"vector_id": "pi_001"})
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    from opentelemetry import trace as _otel_trace

    _HAS_OTEL = True
except ImportError:  # pragma: no cover - tested via mock
    _HAS_OTEL = False
    _otel_trace = None  # type: ignore[assignment]


# ── No-op implementation ──────────────────────────────────────────────


class NoOpSpan:
    """Minimal span that silently discards all operations."""

    __slots__ = ()

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_attributes(self, attributes: dict[str, Any]) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass

    def set_status(self, status: Any, description: str | None = None) -> None:
        pass

    def record_exception(
        self, exception: BaseException, attributes: dict[str, Any] | None = None
    ) -> None:
        pass

    def end(self) -> None:
        pass

    def __enter__(self) -> NoOpSpan:
        return self

    def __exit__(self, *args: object) -> None:
        pass


_NOOP_SPAN = NoOpSpan()


class NoOpTracer:
    """Minimal tracer that always returns :class:`NoOpSpan`."""

    __slots__ = ()

    @contextmanager
    def start_as_current_span(
        self,
        name: str,
        **kwargs: Any,
    ) -> Iterator[NoOpSpan]:
        yield _NOOP_SPAN

    def start_span(self, name: str, **kwargs: Any) -> NoOpSpan:
        return _NOOP_SPAN


_NOOP_TRACER = NoOpTracer()


# ── Public API ────────────────────────────────────────────────────────


def get_tracer(name: str) -> Any:
    """Return an OTel tracer or a no-op fallback.

    Args:
        name: Instrumentation scope name (typically ``__name__``).

    Returns:
        An OpenTelemetry ``Tracer`` when the SDK is installed, or a
        :class:`NoOpTracer` otherwise.
    """
    if _HAS_OTEL and _otel_trace is not None:
        return _otel_trace.get_tracer(name)
    return _NOOP_TRACER


def configure_console_exporter() -> None:
    """Set up a simple console span exporter for CLI use.

    Call this once at startup (e.g. when ``--otel`` is passed).
    Does nothing if OpenTelemetry SDK is not installed.
    """
    if not _HAS_OTEL:
        return

    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )

        provider = TracerProvider()
        processor = BatchSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
        _otel_trace.set_tracer_provider(provider)  # type: ignore[union-attr,unused-ignore]
    except ImportError:
        pass
