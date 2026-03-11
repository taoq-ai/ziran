#!/usr/bin/env python3
"""Run a ZIRAN scan with OpenTelemetry console span exporter.

Usage:
    python otel_console_scan.py <target_url>

Example:
    python otel_console_scan.py http://localhost:8000
"""

from __future__ import annotations

import asyncio
import sys

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.domain.entities.phase import CoverageLevel
from ziran.infrastructure.adapters.http_agent import HttpAgentAdapter
from ziran.infrastructure.telemetry.tracing import configure_console_exporter


async def main(target_url: str) -> None:
    # Enable OTel console exporter — spans print to stderr
    configure_console_exporter()
    print("[otel] Console exporter enabled — spans will print to stderr\n")

    # Create adapter and scanner
    adapter = HttpAgentAdapter(base_url=target_url)
    scanner = AgentScanner(adapter=adapter)

    # Run a quick scan
    result = await scanner.run_campaign(coverage=CoverageLevel.QUICK)

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"Campaign:        {result.campaign_id}")
    print(f"Trust Score:     {result.trust_score:.2f}")
    print(f"Vulnerabilities: {result.total_vulnerabilities}")
    print(f"Phases:          {len(result.phases)}")
    print(f"Duration:        {result.duration_seconds:.1f}s")
    print(f"{'=' * 60}")

    for phase in result.phases:
        vuln_count = len(phase.vulnerabilities_found)
        status = "VULNERABLE" if vuln_count > 0 else "CLEAN"
        print(f"  {phase.phase.value:30s} [{status}] vulns={vuln_count}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python otel_console_scan.py <target_url>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
