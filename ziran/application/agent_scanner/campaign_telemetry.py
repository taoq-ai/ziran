"""Campaign-level telemetry extracted from :mod:`scanner`.

Drives the OTel campaign span *and* the campaign metrics counters in one
place so the orchestrator stays a single call at start and end (and under
its architecture-guard line budget). Both span and metrics fall back to
no-ops when the OTel SDK / exporters are absent.
"""

from __future__ import annotations

from typing import Any

from ziran.infrastructure.telemetry import metrics
from ziran.infrastructure.telemetry.tracing import get_tracer

_tracer = get_tracer(__name__)


def start_campaign_span(
    *,
    campaign_id: str,
    phase_count: int,
    coverage_level: str,
    strategy_name: str,
    resumed: bool,
) -> Any:
    """Start the campaign root span and record the campaigns-started counter."""
    metrics.campaign_started(campaign_id, coverage_level)
    return _tracer.start_span(
        "ziran.campaign",
        attributes={
            "ziran.campaign_id": campaign_id,
            "ziran.phase_count": phase_count,
            "ziran.coverage": coverage_level,
            "ziran.strategy": strategy_name,
            "ziran.resumed": resumed,
        },
    )


def finish_campaign_span(
    span: Any,
    *,
    campaign_id: str,
    coverage_level: str,
    total_vulnerabilities: int,
    trust_score: float,
    duration_seconds: float,
    total_tokens: int,
    dangerous_chain_count: int,
) -> None:
    """Finalize the campaign span and record the campaigns-completed counter."""
    metrics.campaign_completed(campaign_id, coverage_level)
    if span is None:
        return
    span.set_attribute("ziran.total_vulnerabilities", total_vulnerabilities)
    span.set_attribute("ziran.trust_score", trust_score)
    span.set_attribute("ziran.duration_seconds", duration_seconds)
    span.set_attribute("ziran.total_tokens", total_tokens)
    span.set_attribute("ziran.dangerous_chain_count", dangerous_chain_count)
    span.end()
