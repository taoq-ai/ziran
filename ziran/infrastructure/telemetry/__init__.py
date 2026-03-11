"""OpenTelemetry integration for ZIRAN.

Provides opt-in distributed tracing. When ``opentelemetry-api`` is
installed, real spans are emitted. Otherwise a zero-overhead no-op
implementation is used.

Usage::

    from ziran.infrastructure.telemetry.tracing import get_tracer

    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("my.operation") as span:
        span.set_attribute("key", "value")
"""
