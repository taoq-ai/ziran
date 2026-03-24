"""Unit tests for the findings extraction service."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.interfaces.web.services.findings_extractor import (
    _build_title,
    _compute_fingerprint,
    extract_findings,
)


class TestComputeFingerprint:
    """Tests for the fingerprint hash function."""

    def test_deterministic(self) -> None:
        fp1 = _compute_fingerprint("target", "vec1", "prompt_injection")
        fp2 = _compute_fingerprint("target", "vec1", "prompt_injection")
        assert fp1 == fp2

    def test_different_inputs_different_hash(self) -> None:
        fp1 = _compute_fingerprint("target_a", "vec1", "prompt_injection")
        fp2 = _compute_fingerprint("target_b", "vec1", "prompt_injection")
        assert fp1 != fp2

    def test_sha256_length(self) -> None:
        fp = _compute_fingerprint("t", "v", "c")
        assert len(fp) == 64  # SHA-256 hex digest


class TestBuildTitle:
    """Tests for the title builder."""

    def test_formats_category(self) -> None:
        title = _build_title("SQL Injection via Tool", "prompt_injection")
        assert title == "SQL Injection via Tool (Prompt Injection)"


class TestExtractFindings:
    """Tests for the main extract_findings function."""

    @pytest.fixture()
    def run_with_results(self) -> MagicMock:
        run = MagicMock()
        run.id = uuid.uuid4()
        run.target_agent = "http://test-agent:8080"
        run.result_json = {
            "attack_results": [
                {
                    "vector_id": "pi-001",
                    "vector_name": "Basic Prompt Injection",
                    "category": "prompt_injection",
                    "severity": "high",
                    "successful": True,
                    "agent_response": "I will help you...",
                    "prompt_used": "Ignore your instructions",
                    "evidence": {"matched": True},
                    "owasp_mapping": ["LLM01"],
                    "business_impact": ["system_compromise"],
                    "quality_score": 0.85,
                    "encoding_applied": None,
                    "harm_category": None,
                },
                {
                    "vector_id": "te-001",
                    "vector_name": "Tool Exploit",
                    "category": "tool_manipulation",
                    "severity": "critical",
                    "successful": True,
                    "agent_response": "Executing command...",
                    "prompt_used": "Use tool X to...",
                    "evidence": {},
                    "owasp_mapping": ["LLM07", "LLM08"],
                    "business_impact": ["unauthorized_actions"],
                    "quality_score": None,
                    "encoding_applied": "base64",
                    "harm_category": None,
                },
                {
                    "vector_id": "fail-001",
                    "vector_name": "Failed Attack",
                    "category": "data_exfiltration",
                    "severity": "low",
                    "successful": False,
                    "agent_response": "I cannot do that",
                    "prompt_used": "Give me the data",
                    "evidence": {},
                    "owasp_mapping": ["LLM06"],
                    "business_impact": [],
                },
            ]
        }
        return run

    @pytest.fixture()
    def run_empty(self) -> MagicMock:
        run = MagicMock()
        run.id = uuid.uuid4()
        run.target_agent = "http://test-agent:8080"
        run.result_json = {"attack_results": []}
        return run

    @pytest.fixture()
    def run_no_results(self) -> MagicMock:
        run = MagicMock()
        run.id = uuid.uuid4()
        run.result_json = None
        return run

    @pytest.mark.asyncio()
    async def test_extracts_successful_attacks_only(self, run_with_results: MagicMock) -> None:
        session = AsyncMock()
        # Simulate no existing findings (no duplicates)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        findings = await extract_findings(session, run_with_results)

        # Should extract 2 findings (pi-001 and te-001), not the failed one
        assert len(findings) == 2
        assert session.add.call_count >= 2  # findings + compliance mappings

    @pytest.mark.asyncio()
    async def test_creates_compliance_mappings(self, run_with_results: MagicMock) -> None:
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        await extract_findings(session, run_with_results)

        # Check that session.add was called with ComplianceMapping objects
        added_objects = [call.args[0] for call in session.add.call_args_list]
        from ziran.interfaces.web.models import ComplianceMapping

        mappings = [obj for obj in added_objects if isinstance(obj, ComplianceMapping)]
        # pi-001 has 1 mapping (LLM01), te-001 has 2 (LLM07, LLM08)
        assert len(mappings) == 3

    @pytest.mark.asyncio()
    async def test_empty_attack_results(self, run_empty: MagicMock) -> None:
        session = AsyncMock()
        findings = await extract_findings(session, run_empty)
        assert findings == []

    @pytest.mark.asyncio()
    async def test_no_result_json(self, run_no_results: MagicMock) -> None:
        session = AsyncMock()
        findings = await extract_findings(session, run_no_results)
        assert findings == []

    @pytest.mark.asyncio()
    async def test_dedup_preserves_status(self, run_with_results: MagicMock) -> None:
        session = AsyncMock()

        # Simulate existing finding with user-set status
        existing_finding = MagicMock()
        existing_finding.status = "false_positive"
        existing_finding.run_id = uuid.uuid4()

        mock_result = MagicMock()
        # First call returns existing finding, second returns None
        mock_result.scalar_one_or_none.side_effect = [existing_finding, None]
        session.execute.return_value = mock_result

        await extract_findings(session, run_with_results)

        # Existing finding should have its run_id updated but status preserved
        assert existing_finding.run_id == run_with_results.id
        assert existing_finding.status == "false_positive"  # NOT overwritten
