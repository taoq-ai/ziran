"""Unit tests for the ExportService."""

from __future__ import annotations

import pytest

from ziran.application.policy_export.export_service import ExportService
from ziran.domain.entities.phase import CampaignResult
from ziran.infrastructure.policy_renderers.rego_renderer import RegoRenderer


def _make_result(
    chains: list[dict[str, object]] | None = None,
) -> CampaignResult:
    """Build a minimal CampaignResult with given dangerous chains."""
    return CampaignResult(
        campaign_id="test-campaign",
        target_agent="test-agent",
        phases_executed=[],
        total_vulnerabilities=0,
        final_trust_score=0.5,
        success=False,
        dangerous_tool_chains=chains or [],
    )


def _chain_dict(
    risk_level: str = "critical",
    tools: list[str] | None = None,
) -> dict[str, object]:
    return {
        "tools": tools or ["read_file", "http_request"],
        "risk_level": risk_level,
        "vulnerability_type": "data_exfiltration",
        "exploit_description": "Test chain",
    }


@pytest.mark.unit
class TestExportService:
    def test_severity_floor_filters_low(self) -> None:
        """Only chains at or above the floor are exported."""
        chains = [
            _chain_dict(risk_level="critical"),
            _chain_dict(risk_level="low"),
            _chain_dict(risk_level="high"),
        ]
        result = _make_result(chains)
        service = ExportService(RegoRenderer())

        policies = service.export(result, severity_floor="high")

        assert len(policies) == 2
        severities = {p.severity for p in policies}
        assert severities == {"critical", "high"}

    def test_empty_chains_returns_empty(self) -> None:
        result = _make_result(chains=[])
        service = ExportService(RegoRenderer())

        policies = service.export(result)

        assert policies == []

    def test_skip_counting(self) -> None:
        """Skipped policies are still included in the list."""
        from ziran.infrastructure.policy_renderers.cedar_renderer import (
            CedarRenderer,
        )

        chains = [
            _chain_dict(
                tools=["a", "b", "c"],
                risk_level="critical",
            ),
        ]
        result = _make_result(chains)
        service = ExportService(CedarRenderer())

        policies = service.export(result)

        assert len(policies) == 1
        assert policies[0].skipped

    def test_finding_id_format(self) -> None:
        chains = [_chain_dict()]
        result = _make_result(chains)
        service = ExportService(RegoRenderer())

        policies = service.export(result)

        assert len(policies) == 1
        assert policies[0].finding_id == "ZIRAN-test-campaign-000"
