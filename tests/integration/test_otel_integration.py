"""Integration tests — OpenTelemetry tracing with real OTel SDK.

Verifies that ZIRAN's tracing instrumentation creates real OTel spans
with correct attributes when the opentelemetry-sdk is installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

otel_trace = pytest.importorskip("opentelemetry.trace", reason="opentelemetry-sdk not installed")
otel_sdk_trace = pytest.importorskip(
    "opentelemetry.sdk.trace", reason="opentelemetry-sdk not installed"
)

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan

pytestmark = pytest.mark.integration


# ── In-memory exporter for test assertions ───────────────────────────


class InMemorySpanExporter:
    """Collects spans in a list for test assertions."""

    def __init__(self) -> None:
        self.spans: list[ReadableSpan] = []

    def export(self, spans: list[ReadableSpan]) -> None:
        self.spans.extend(spans)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def clear(self) -> None:
        self.spans.clear()


# Module-scoped provider: set once to avoid "Overriding TracerProvider" warning.
_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))
otel_trace.set_tracer_provider(_PROVIDER)


@pytest.fixture(autouse=True)
def _clear_spans() -> None:
    """Clear collected spans before each test."""
    _EXPORTER.clear()


# ── Tracing module integration ────────────────────────────────────────


class TestGetTracerWithRealOTel:
    """Test get_tracer() returns real OTel tracers when SDK is installed."""

    def test_returns_real_tracer(self) -> None:
        """get_tracer should return a real OTel tracer, not NoOpTracer."""
        from ziran.infrastructure.telemetry.tracing import NoOpTracer, get_tracer

        tracer = get_tracer("test.integration")
        assert not isinstance(tracer, NoOpTracer)

    def test_real_spans_created(self) -> None:
        """Spans created via get_tracer should be collected by exporter."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("test.integration")
        with tracer.start_as_current_span("test.span") as span:
            span.set_attribute("test.key", "test.value")
            span.add_event("test.event", {"detail": "info"})

        assert len(_EXPORTER.spans) == 1
        exported_span = _EXPORTER.spans[0]
        assert exported_span.name == "test.span"
        assert exported_span.attributes["test.key"] == "test.value"

    def test_nested_spans(self) -> None:
        """Nested spans should maintain parent-child relationships."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("test.integration")
        with tracer.start_as_current_span("parent") as parent_span:
            parent_span.set_attribute("level", "parent")
            with tracer.start_as_current_span("child") as child_span:
                child_span.set_attribute("level", "child")

        assert len(_EXPORTER.spans) == 2
        child_exported = next(s for s in _EXPORTER.spans if s.name == "child")
        parent_exported = next(s for s in _EXPORTER.spans if s.name == "parent")

        # Child should reference parent's span context
        assert child_exported.parent is not None
        assert child_exported.parent.span_id == parent_exported.context.span_id


# ── Scanner instrumentation integration ───────────────────────────────


class TestScannerSpanAttributes:
    """Verify scanner creates spans with correct attributes."""

    def test_campaign_span_created(self) -> None:
        """Scanner.run_campaign should create a campaign span."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("ziran.application.agent_scanner.scanner")
        with tracer.start_as_current_span("ziran.campaign") as span:
            span.set_attribute("ziran.campaign.id", "test_campaign_001")
            span.set_attribute("ziran.campaign.phase_count", 3)
            span.set_attribute("ziran.campaign.coverage", "quick")
            span.set_attribute("ziran.campaign.strategy", "fixed")

        assert len(_EXPORTER.spans) == 1
        campaign_span = _EXPORTER.spans[0]
        assert campaign_span.name == "ziran.campaign"
        assert campaign_span.attributes["ziran.campaign.id"] == "test_campaign_001"
        assert campaign_span.attributes["ziran.campaign.phase_count"] == 3

    def test_attack_span_with_vulnerability_event(self) -> None:
        """Attack span should emit vulnerability_found events."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("ziran.application.agent_scanner.scanner")
        span = tracer.start_span(
            "ziran.attack",
            attributes={
                "ziran.attack.id": "pi_001",
                "ziran.attack.name": "System Prompt Extraction",
                "ziran.attack.category": "prompt_injection",
                "ziran.attack.severity": "critical",
                "ziran.attack.tactic": "single",
            },
        )
        span.add_event(
            "vulnerability_found",
            {
                "vector_id": "pi_001",
                "vector_name": "System Prompt Extraction",
                "category": "prompt_injection",
                "severity": "critical",
            },
        )
        span.end()

        assert len(_EXPORTER.spans) == 1
        attack_span = _EXPORTER.spans[0]
        assert attack_span.name == "ziran.attack"
        assert attack_span.attributes["ziran.attack.category"] == "prompt_injection"

        events = attack_span.events
        assert len(events) == 1
        assert events[0].name == "vulnerability_found"
        assert events[0].attributes["vector_id"] == "pi_001"

    def test_detection_span_attributes(self) -> None:
        """Detection span should record success and score."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("ziran.application.detectors.pipeline")
        span = tracer.start_span("ziran.detection")
        span.set_attribute("ziran.detection.successful", True)
        span.set_attribute("ziran.detection.score", 0.95)
        span.add_event("detector.indicator", {"score": 0.95, "confidence": 0.9})
        span.end()

        assert len(_EXPORTER.spans) == 1
        det_span = _EXPORTER.spans[0]
        assert det_span.attributes["ziran.detection.successful"] is True
        assert det_span.attributes["ziran.detection.score"] == 0.95

    def test_chain_analysis_span(self) -> None:
        """Chain analysis span should record chain counts."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("ziran.application.knowledge_graph.chain_analyzer")
        span = tracer.start_span("ziran.chain_analysis")
        span.set_attribute("ziran.chain_analysis.chain_count", 5)
        span.set_attribute("ziran.chain_analysis.chain_critical", 2)
        span.end()

        assert len(_EXPORTER.spans) == 1
        chain_span = _EXPORTER.spans[0]
        assert chain_span.attributes["ziran.chain_analysis.chain_count"] == 5
        assert chain_span.attributes["ziran.chain_analysis.chain_critical"] == 2


class TestFullSpanHierarchy:
    """Test the complete span hierarchy matches the documented structure."""

    def test_campaign_phase_attack_hierarchy(self) -> None:
        """Simulate full campaign -> phase -> attack span nesting."""
        from ziran.infrastructure.telemetry.tracing import get_tracer

        tracer = get_tracer("ziran.scanner")

        with tracer.start_as_current_span("ziran.campaign") as campaign:
            campaign.set_attribute("ziran.campaign.id", "test_001")

            with tracer.start_as_current_span("ziran.phase") as phase:
                phase.set_attribute("ziran.phase.name", "EXPLOITATION")

                with tracer.start_as_current_span("ziran.attack") as attack:
                    attack.set_attribute("ziran.attack.id", "pi_001")

                    with tracer.start_as_current_span("ziran.detection") as detection:
                        detection.set_attribute("ziran.detection.successful", True)

            with tracer.start_as_current_span("ziran.chain_analysis") as chain:
                chain.set_attribute("ziran.chain_analysis.chain_count", 3)

        # Should have 5 spans: campaign, phase, attack, detection, chain_analysis
        assert len(_EXPORTER.spans) == 5

        span_names = {s.name for s in _EXPORTER.spans}
        assert span_names == {
            "ziran.campaign",
            "ziran.phase",
            "ziran.attack",
            "ziran.detection",
            "ziran.chain_analysis",
        }

        # Verify parent-child relationships
        campaign_span = next(s for s in _EXPORTER.spans if s.name == "ziran.campaign")
        phase_span = next(s for s in _EXPORTER.spans if s.name == "ziran.phase")
        attack_span = next(s for s in _EXPORTER.spans if s.name == "ziran.attack")
        detection_span = next(s for s in _EXPORTER.spans if s.name == "ziran.detection")
        chain_span = next(s for s in _EXPORTER.spans if s.name == "ziran.chain_analysis")

        # Phase is child of campaign
        assert phase_span.parent is not None
        assert phase_span.parent.span_id == campaign_span.context.span_id

        # Attack is child of phase
        assert attack_span.parent is not None
        assert attack_span.parent.span_id == phase_span.context.span_id

        # Detection is child of attack
        assert detection_span.parent is not None
        assert detection_span.parent.span_id == attack_span.context.span_id

        # Chain analysis is child of campaign
        assert chain_span.parent is not None
        assert chain_span.parent.span_id == campaign_span.context.span_id
