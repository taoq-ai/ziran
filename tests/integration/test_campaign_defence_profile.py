"""Integration tests for defence-profile wiring (spec 012 US5).

Verifies both the "profile declared" path (report gains a Declared Defences
section and an evasion-rate field) and the "no profile" path (report is
byte-identical to pre-spec-012 output for the same campaign data).
"""

from __future__ import annotations

import json

import pytest

from ziran.domain.entities.attack import AttackCategory, AttackResult
from ziran.domain.entities.defence import DefenceDeclaration, DefenceProfile
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase
from ziran.interfaces.cli.reports import ReportGenerator


def _make_campaign_result(
    *,
    campaign_id: str = "test-campaign",
    defence_profile: DefenceProfile | None = None,
    evasion_rate: float | None = None,
) -> CampaignResult:
    return CampaignResult(
        campaign_id=campaign_id,
        target_agent="test-agent",
        phases_executed=[
            PhaseResult(
                phase=ScanPhase.EXECUTION,
                duration_seconds=1.0,
                vulnerabilities_found=[],
                discovered_capabilities=[],
                trust_score=0.8,
                success=True,
            )
        ],
        total_vulnerabilities=0,
        critical_paths=[],
        final_trust_score=0.8,
        success=False,
        attack_results=[
            AttackResult(
                vector_id="v1",
                vector_name="v1",
                category=AttackCategory.PROMPT_INJECTION,
                severity="low",
                successful=False,
            ).model_dump(mode="json"),
        ],
        coverage_level="standard",
        defence_profile=defence_profile,
        evasion_rate=evasion_rate,
    )


class TestCampaignWithDefenceProfile:
    @pytest.mark.integration
    def test_json_report_includes_defence_profile_when_declared(self, tmp_path) -> None:
        profile = DefenceProfile(
            name="prod-ingress-v1",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="nemo-guardrails@v0.8"),
                DefenceDeclaration(kind="output_guard", identifier="lakera-guard@2025-09"),
            ],
        )
        result = _make_campaign_result(defence_profile=profile)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_json(result)
        data = json.loads(path.read_text())
        assert data["defence_profile"]["name"] == "prod-ingress-v1"
        assert len(data["defence_profile"]["defences"]) == 2
        # No evaluable defences → evasion_rate is omitted from JSON
        assert "evasion_rate" not in data

    @pytest.mark.integration
    def test_markdown_report_includes_declared_defences_section(self, tmp_path) -> None:
        profile = DefenceProfile(
            name="prod-v1",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="nemo@v0.8"),
            ],
        )
        result = _make_campaign_result(defence_profile=profile)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_markdown(result)
        content = path.read_text()
        assert "## Declared Defences" in content
        assert "prod-v1" in content
        assert "nemo@v0.8" in content
        assert "not computable" in content  # No evaluable defences in this release

    @pytest.mark.integration
    def test_json_report_includes_evasion_rate_when_computable(self, tmp_path) -> None:
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="custom-guard", evaluable=True),
            ],
        )
        result = _make_campaign_result(defence_profile=profile, evasion_rate=0.25)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_json(result)
        data = json.loads(path.read_text())
        assert data["evasion_rate"] == 0.25


class TestCampaignWithoutDefenceProfile:
    @pytest.mark.integration
    def test_json_report_omits_defence_fields(self, tmp_path) -> None:
        result = _make_campaign_result(defence_profile=None, evasion_rate=None)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_json(result)
        data = json.loads(path.read_text())
        # FR-017 / SC-005: byte-identity with pre-spec-012 output.
        assert "defence_profile" not in data
        assert "evasion_rate" not in data

    @pytest.mark.integration
    def test_markdown_report_has_no_declared_defences_section(self, tmp_path) -> None:
        result = _make_campaign_result(defence_profile=None)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_markdown(result)
        content = path.read_text()
        assert "Declared Defences" not in content
        assert "Evasion rate" not in content

    @pytest.mark.integration
    def test_empty_profile_treated_as_absent(self, tmp_path) -> None:
        # FR-017: empty profile == no profile at all
        profile = DefenceProfile(name="placeholder")
        result = _make_campaign_result(defence_profile=profile)
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_markdown(result)
        content = path.read_text()
        assert "Declared Defences" not in content
