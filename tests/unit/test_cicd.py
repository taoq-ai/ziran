"""Unit tests for CI/CD Integration (Feature 5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from koan.application.cicd.gate import QualityGate
from koan.application.cicd.github_actions import (
    emit_annotations,
    set_output,
    write_step_summary,
)
from koan.application.cicd.sarif import generate_sarif, write_sarif
from koan.domain.entities.ci import (
    FindingCount,
    GateResult,
    GateStatus,
    QualityGateConfig,
    SeverityThresholds,
)
from koan.domain.entities.phase import CampaignResult

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _make_campaign(
    *,
    trust: float = 0.8,
    attacks: list[dict[str, Any]] | None = None,
    success: bool = False,
) -> CampaignResult:
    """Build a minimal CampaignResult for testing."""
    return CampaignResult(
        campaign_id="test_campaign_001",
        target_agent="test_agent",
        phases_executed=[],
        total_vulnerabilities=0,
        final_trust_score=trust,
        success=success,
        attack_results=attacks or [],
    )


def _make_attack(
    *,
    vector_id: str = "test_vec",
    vector_name: str = "Test Vector",
    category: str = "prompt_injection",
    severity: str = "high",
    successful: bool = True,
    owasp: list[str] | None = None,
    agent_response: str = "I'll do that",
    prompt_used: str = "ignore instructions",
) -> dict[str, Any]:
    return {
        "vector_id": vector_id,
        "vector_name": vector_name,
        "category": category,
        "severity": severity,
        "successful": successful,
        "evidence": {"indicator": "compliance"},
        "agent_response": agent_response,
        "prompt_used": prompt_used,
        "owasp_mapping": owasp or ["LLM01"],
    }


@pytest.fixture()
def clean_campaign() -> CampaignResult:
    """Campaign with no findings."""
    return _make_campaign(trust=0.95)


@pytest.fixture()
def risky_campaign() -> CampaignResult:
    """Campaign with critical findings."""
    return _make_campaign(
        trust=0.3,
        success=True,
        attacks=[
            _make_attack(severity="critical", vector_id="crit1"),
            _make_attack(severity="critical", vector_id="crit2"),
            _make_attack(severity="high", vector_id="high1"),
            _make_attack(severity="medium", vector_id="med1", successful=False),
        ],
    )


# ──────────────────────────────────────────────────────────────────────
# Tests — Domain Models
# ──────────────────────────────────────────────────────────────────────


class TestDomainModels:
    def test_severity_thresholds_defaults(self) -> None:
        t = SeverityThresholds()
        assert t.critical == 0
        assert t.high == -1
        assert t.max_for("critical") == 0

    def test_finding_count_total(self) -> None:
        fc = FindingCount(critical=1, high=2, medium=3, low=4)
        assert fc.total == 10

    def test_gate_result_exit_code_passed(self) -> None:
        gr = GateResult(status=GateStatus.PASSED, trust_score=0.9)
        assert gr.exit_code == 0
        assert gr.passed

    def test_gate_result_exit_code_failed(self) -> None:
        gr = GateResult(status=GateStatus.FAILED, trust_score=0.1)
        assert gr.exit_code == 1
        assert not gr.passed

    def test_quality_gate_config_defaults(self) -> None:
        cfg = QualityGateConfig()
        assert cfg.min_trust_score == 0.0
        assert cfg.max_critical_findings == 0
        assert cfg.fail_on_policy_violation is True


# ──────────────────────────────────────────────────────────────────────
# Tests — Quality Gate
# ──────────────────────────────────────────────────────────────────────


class TestQualityGate:
    def test_clean_passes(self, clean_campaign: CampaignResult) -> None:
        gate = QualityGate()
        result = gate.evaluate(clean_campaign)
        assert result.passed
        assert result.exit_code == 0
        assert result.finding_counts.total == 0

    def test_critical_findings_fail(self, risky_campaign: CampaignResult) -> None:
        gate = QualityGate()
        result = gate.evaluate(risky_campaign)
        assert not result.passed
        assert result.finding_counts.critical == 2
        assert any(v.rule == "max_critical_findings" for v in result.violations)

    def test_trust_score_threshold(self) -> None:
        campaign = _make_campaign(trust=0.4)
        gate = QualityGate(QualityGateConfig(min_trust_score=0.7))
        result = gate.evaluate(campaign)
        assert not result.passed
        assert any(v.rule == "min_trust_score" for v in result.violations)

    def test_trust_score_disabled(self) -> None:
        campaign = _make_campaign(trust=0.1)
        gate = QualityGate(QualityGateConfig(min_trust_score=0.0))
        result = gate.evaluate(campaign)
        # No trust-score violation when min is 0.0
        assert not any(v.rule == "min_trust_score" for v in result.violations)

    def test_severity_thresholds(self) -> None:
        attacks = [_make_attack(severity="high", vector_id=f"h{i}") for i in range(5)]
        campaign = _make_campaign(attacks=attacks)
        cfg = QualityGateConfig(
            max_critical_findings=-1,  # unlimited
            severity_thresholds=SeverityThresholds(critical=-1, high=3),
        )
        gate = QualityGate(cfg)
        result = gate.evaluate(campaign)
        assert not result.passed
        assert any(v.rule == "severity_threshold_high" for v in result.violations)

    def test_policy_violation_flag(self) -> None:
        campaign = _make_campaign(success=True)
        gate = QualityGate(
            QualityGateConfig(
                max_critical_findings=-1,
                fail_on_policy_violation=True,
            )
        )
        result = gate.evaluate(campaign)
        assert any(v.rule == "policy_violation" for v in result.violations)

    def test_policy_violation_disabled(self) -> None:
        campaign = _make_campaign(success=True)
        gate = QualityGate(
            QualityGateConfig(
                max_critical_findings=-1,
                fail_on_policy_violation=False,
            )
        )
        result = gate.evaluate(campaign)
        assert not any(v.rule == "policy_violation" for v in result.violations)

    def test_summary_present(self, clean_campaign: CampaignResult) -> None:
        gate = QualityGate()
        result = gate.evaluate(clean_campaign)
        assert "Gate:" in result.summary
        assert "Trust:" in result.summary

    def test_from_yaml(self, tmp_path: Path) -> None:
        import yaml

        config_data = {
            "min_trust_score": 0.5,
            "max_critical_findings": 2,
            "severity_thresholds": {"critical": 2, "high": 5},
        }
        yaml_path = tmp_path / "gate.yaml"
        yaml_path.write_text(yaml.dump(config_data))

        gate = QualityGate.from_yaml(yaml_path)
        assert gate.config.min_trust_score == 0.5
        assert gate.config.max_critical_findings == 2
        assert gate.config.severity_thresholds.critical == 2

    def test_from_yaml_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            QualityGate.from_yaml(Path("/nonexistent.yaml"))

    def test_unlimited_critical_allows_all(self) -> None:
        attacks = [_make_attack(severity="critical", vector_id=f"c{i}") for i in range(10)]
        campaign = _make_campaign(attacks=attacks)
        gate = QualityGate(
            QualityGateConfig(
                max_critical_findings=-1,
                fail_on_policy_violation=False,
                severity_thresholds=SeverityThresholds(critical=-1),
            )
        )
        result = gate.evaluate(campaign)
        assert result.passed


# ──────────────────────────────────────────────────────────────────────
# Tests — SARIF Generator
# ──────────────────────────────────────────────────────────────────────


class TestSarif:
    def test_sarif_structure(self, risky_campaign: CampaignResult) -> None:
        sarif = generate_sarif(risky_campaign)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "KOAN"
        assert len(run["results"]) > 0

    def test_sarif_rules_created(self, risky_campaign: CampaignResult) -> None:
        sarif = generate_sarif(risky_campaign)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # Only successful attacks get rules
        rule_ids = {r["id"] for r in rules}
        assert "crit1" in rule_ids
        assert "high1" in rule_ids

    def test_sarif_severity_mapping(self, risky_campaign: CampaignResult) -> None:
        sarif = generate_sarif(risky_campaign)
        results = sarif["runs"][0]["results"]
        crit = next(r for r in results if r["ruleId"] == "crit1")
        assert crit["level"] == "error"

    def test_sarif_empty_campaign(self, clean_campaign: CampaignResult) -> None:
        sarif = generate_sarif(clean_campaign)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_has_owasp_tags(self, risky_campaign: CampaignResult) -> None:
        sarif = generate_sarif(risky_campaign)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            tags = rule.get("properties", {}).get("tags", [])
            assert any(t.startswith("owasp/") for t in tags)

    def test_write_sarif_file(self, tmp_path: Path, risky_campaign: CampaignResult) -> None:
        out = tmp_path / "out.sarif"
        result_path = write_sarif(risky_campaign, out)
        assert result_path == out
        assert out.exists()
        sarif = json.loads(out.read_text())
        assert sarif["version"] == "2.1.0"


# ──────────────────────────────────────────────────────────────────────
# Tests — GitHub Actions Helpers
# ──────────────────────────────────────────────────────────────────────


class TestGitHubActions:
    def test_annotations_generated(self, risky_campaign: CampaignResult) -> None:
        annotations = emit_annotations(risky_campaign)
        assert len(annotations) > 0
        assert all(a.startswith("::") for a in annotations)

    def test_annotations_levels(self, risky_campaign: CampaignResult) -> None:
        annotations = emit_annotations(risky_campaign)
        assert any("::error" in a for a in annotations)

    def test_no_annotations_for_clean(self, clean_campaign: CampaignResult) -> None:
        annotations = emit_annotations(clean_campaign)
        assert len(annotations) == 0

    def test_step_summary_content(self, risky_campaign: CampaignResult) -> None:
        gate = QualityGate()
        gate_result = gate.evaluate(risky_campaign)
        summary = write_step_summary(gate_result, risky_campaign)
        assert "KOAN Security Gate" in summary
        assert "test_agent" in summary
        assert "Critical" in summary

    def test_step_summary_writes_file(self, tmp_path: Path, risky_campaign: CampaignResult) -> None:
        gate = QualityGate()
        gate_result = gate.evaluate(risky_campaign)
        summary_file = tmp_path / "summary.md"
        write_step_summary(
            gate_result,
            risky_campaign,
            summary_path=str(summary_file),
        )
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "KOAN Security Gate" in content

    def test_set_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        output_file = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        line = set_output("status", "passed")
        assert line == "status=passed"
        assert "status=passed" in output_file.read_text()

    def test_set_output_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        line = set_output("foo", "bar")
        assert line == "foo=bar"

    def test_summary_passed_emoji(self, clean_campaign: CampaignResult) -> None:
        gate = QualityGate()
        gate_result = gate.evaluate(clean_campaign)
        summary = write_step_summary(gate_result, clean_campaign)
        assert "PASSED" in summary

    def test_summary_vulnerabilities_table(self, risky_campaign: CampaignResult) -> None:
        gate = QualityGate()
        gate_result = gate.evaluate(risky_campaign)
        summary = write_step_summary(gate_result, risky_campaign)
        assert "Vulnerabilities Found" in summary
