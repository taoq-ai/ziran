"""Integration test: a scan with JSON logging emits only valid JSON log lines.

Acceptance for spec-030: every stderr log line during a campaign is a single
valid JSON object carrying the required base fields, and campaign/phase/vector
context is merged in where the scanner has bound it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.infrastructure.logging.context import clear_context
from ziran.infrastructure.logging.logger import setup_logging

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

REQUIRED_FIELDS = {"timestamp", "level", "logger", "event"}


@pytest.mark.integration
async def test_json_scan_emits_only_valid_json_lines(
    shared_attack_library: AttackLibrary, capsys: pytest.CaptureFixture[str]
) -> None:
    clear_context()
    setup_logging(level="INFO", log_format="json")

    adapter = MockAgentAdapter(vulnerable=True)
    scanner = AgentScanner(adapter=adapter, attack_library=shared_attack_library)
    await scanner.run_campaign(
        phases=[ScanPhase.VULNERABILITY_DISCOVERY],
        coverage=CoverageLevel.ESSENTIAL,
        stop_on_critical=False,
    )

    lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]
    assert lines, "expected at least one log line"

    records = []
    for line in lines:
        record = json.loads(line)  # raises if any line is not valid JSON
        assert record.keys() >= REQUIRED_FIELDS, f"missing base fields in: {record}"
        records.append(record)

    # Context binding: campaign_id and phase must appear on campaign-scoped lines.
    assert any(r.get("event") == "campaign_started" for r in records)
    assert any("campaign_id" in r for r in records)
    assert any(r.get("phase") == ScanPhase.VULNERABILITY_DISCOVERY.value for r in records)

    clear_context()
