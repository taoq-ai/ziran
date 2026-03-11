#!/usr/bin/env python3
"""Run a ZIRAN scan with OTLP exporter (Jaeger, Grafana Tempo, etc.).

Requires:
    pip install "ziran[otel]" opentelemetry-exporter-otlp

Environment variables:
    OTEL_EXPORTER_OTLP_ENDPOINT  — Collector endpoint (default: http://localhost:4317)
    OTEL_SERVICE_NAME            — Service name (default: ziran)

Usage:
    OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
    OTEL_SERVICE_NAME=ziran \
      python otel_otlp_scan.py <target_url>
"""

from __future__ import annotations

import asyncio
import os
import sys


def configure_otlp_exporter() -> None:
    """Set up OTLP span exporter with TracerProvider."""
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    service_name = os.environ.get("OTEL_SERVICE_NAME", "ziran")
    resource = Resource.create({"service.name": service_name})

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


async def main(target_url: str) -> None:
    configure_otlp_exporter()

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    print(f"[otel] OTLP exporter configured — sending to {endpoint}\n")

    from ziran.application.agent_scanner.scanner import AgentScanner
    from ziran.domain.entities.phase import CoverageLevel
    from ziran.infrastructure.adapters.http_agent import HttpAgentAdapter

    adapter = HttpAgentAdapter(base_url=target_url)
    scanner = AgentScanner(adapter=adapter)

    result = await scanner.run_campaign(coverage=CoverageLevel.QUICK)

    print(f"\n{'=' * 60}")
    print(f"Campaign:        {result.campaign_id}")
    print(f"Trust Score:     {result.trust_score:.2f}")
    print(f"Vulnerabilities: {result.total_vulnerabilities}")
    print(f"Duration:        {result.duration_seconds:.1f}s")
    print(f"{'=' * 60}")
    print("\nView traces at: http://localhost:16686 (Jaeger UI)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python otel_otlp_scan.py <target_url>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
