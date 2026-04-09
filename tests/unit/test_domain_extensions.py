"""Backward compatibility tests for v0.8 domain extensions.

Verifies that DangerousChain and CampaignResult can still be constructed
with only their original fields, and that new fields serialize/deserialize
correctly.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase


@pytest.mark.unit
class TestDangerousChainBackwardCompat:
    """DangerousChain backward compatibility with new trace fields."""

    def test_construct_with_original_fields_only(self) -> None:
        """New optional fields default when only original fields are supplied."""
        chain = DangerousChain(
            tools=["read_file", "http_request"],
            risk_level="high",
            vulnerability_type="data_exfiltration",
            exploit_description="File content sent over HTTP",
        )
        assert chain.observed_in_production is False
        assert chain.first_seen is None
        assert chain.last_seen is None
        assert chain.occurrence_count == 0
        assert chain.trace_source is None
        # Original fields still work
        assert chain.tools == ["read_file", "http_request"]
        assert chain.risk_level == "high"
        assert chain.chain_type == "direct"

    def test_serialize_deserialize_with_new_fields(self) -> None:
        """Round-trip through model_dump / model_validate preserves trace fields."""
        now = datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC)
        chain = DangerousChain(
            tools=["sql_query", "exec_command"],
            risk_level="critical",
            vulnerability_type="sql_to_rce",
            exploit_description="SQL result piped to shell",
            observed_in_production=True,
            first_seen=now,
            last_seen=now,
            occurrence_count=5,
            trace_source="langfuse",
        )
        data = chain.model_dump()
        restored = DangerousChain.model_validate(data)

        assert restored.observed_in_production is True
        assert restored.first_seen == now
        assert restored.last_seen == now
        assert restored.occurrence_count == 5
        assert restored.trace_source == "langfuse"

    def test_occurrence_count_non_negative(self) -> None:
        """occurrence_count rejects negative values via ge=0 constraint."""
        with pytest.raises(Exception):  # noqa: B017
            DangerousChain(
                tools=["t"],
                risk_level="low",
                vulnerability_type="test",
                exploit_description="test",
                occurrence_count=-1,
            )


@pytest.mark.unit
class TestCampaignResultBackwardCompat:
    """CampaignResult backward compatibility with new source field."""

    @staticmethod
    def _minimal_campaign(**overrides: object) -> CampaignResult:
        """Build a minimal CampaignResult with required fields."""
        defaults: dict[str, object] = {
            "campaign_id": "test-001",
            "target_agent": "demo-agent",
            "phases_executed": [
                PhaseResult(
                    phase=ScanPhase.RECONNAISSANCE,
                    success=True,
                    trust_score=0.5,
                    duration_seconds=1.0,
                )
            ],
            "total_vulnerabilities": 0,
            "final_trust_score": 0.5,
            "success": False,
        }
        defaults.update(overrides)
        return CampaignResult.model_validate(defaults)

    def test_construct_with_original_fields_only(self) -> None:
        """source defaults to 'scan' when not supplied."""
        result = self._minimal_campaign()
        assert result.source == "scan"

    def test_serialize_deserialize_with_trace_source(self) -> None:
        """Round-trip preserves source='trace-analysis'."""
        result = self._minimal_campaign(source="trace-analysis")
        data = result.model_dump()
        restored = CampaignResult.model_validate(data)
        assert restored.source == "trace-analysis"

    def test_source_in_serialized_output(self) -> None:
        """source field appears in model_dump output."""
        result = self._minimal_campaign(source="trace-analysis")
        data = result.model_dump()
        assert "source" in data
        assert data["source"] == "trace-analysis"
