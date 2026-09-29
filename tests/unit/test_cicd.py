"""Unit tests for CI/CD Integration (Feature 5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ziran.application.cicd.gate import QualityGate
from ziran.application.cicd.github_actions import (
    emit_annotations,
    set_output,
    write_step_summary,
)
from ziran.application.cicd.sarif import generate_audit_sarif, generate_sarif, write_sarif
from ziran.application.static_analysis.analyzer import StaticFinding
from ziran.domain.entities.ci import (
    FindingCount,
    GateResult,
    GateStatus,
    QualityGateConfig,
    SeverityThresholds,
)
from ziran.domain.entities.phase import CampaignResult

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _make_campaign(
    *,
    trust: float = 0.8,
    attacks: list[dict[str, Any]] | None = None,
    success: bool = False,
    chains: list[dict[str, Any]] | None = None,
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
        dangerous_tool_chains=chains or [],
        critical_chain_count=len([c for c in (chains or []) if c.get("risk_level") == "critical"]),
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
        assert run["tool"]["driver"]["name"] == "ZIRAN"
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
        assert "ZIRAN Security Gate" in summary
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
        assert "ZIRAN Security Gate" in content

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


# ──────────────────────────────────────────────────────────────────────
# Tests — Composition findings are gated (spec 028)
# ──────────────────────────────────────────────────────────────────────


def _make_chain(*, risk_level: str = "critical") -> dict[str, Any]:
    return {
        "risk_level": risk_level,
        "vulnerability_type": "data_exfiltration",
        "tools": ["search_database", "send_email_report"],
    }


class TestCompositionFindingGating:
    def test_critical_composition_fails_default_gate(self) -> None:
        camp = _make_campaign(trust=0.9, success=True, chains=[_make_chain()])
        result = QualityGate().evaluate(camp)
        assert result.finding_counts.critical == 1
        assert result.status == GateStatus.FAILED
        assert result.passed is False

    def test_composition_counts_alongside_detector_findings(self) -> None:
        camp = _make_campaign(
            attacks=[_make_attack(severity="high", vector_id="h1")],
            chains=[_make_chain(risk_level="high")],
        )
        counts = QualityGate._count_findings(camp)
        assert counts.high == 2  # one detector finding + one composition finding

    def test_clean_campaign_has_no_findings(self, clean_campaign: CampaignResult) -> None:
        assert QualityGate._count_findings(clean_campaign).total == 0


# ──────────────────────────────────────────────────────────────────────
# Tests — SARIF for ``ziran audit`` rows
# ──────────────────────────────────────────────────────────────────────


def _row(check_id: str = "BL001", severity: str = "critical", **kw: Any) -> StaticFinding:
    base: dict[str, Any] = {
        "check_id": check_id,
        "message": f"{check_id} message",
        "severity": severity,
        "file_path": "plug/agents/builder.md",
    }
    return StaticFinding(**{**base, **kw})


class TestAuditSarif:
    @pytest.fixture(autouse=True)
    def _cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)

    def test_envelope_matches_generate_sarif(self, clean_campaign: CampaignResult) -> None:
        doc = generate_audit_sarif([])
        assert doc["version"] == "2.1.0"
        assert doc["$schema"] == generate_sarif(clean_campaign)["$schema"]
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["tool"]["driver"]["name"] == "ZIRAN"
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_baseline_row_maps_to_result(self) -> None:
        row = _row(
            message="Agent 'builder' gains tool 'WebFetch' not in the baseline",
            agent="builder",
            tools=("WebFetch",),
            line_number=4,
        )
        (result,) = generate_audit_sarif([row])["runs"][0]["results"]
        assert result == {
            "ruleId": "BL001",
            "level": "error",
            "message": {"text": "Agent 'builder' gains tool 'WebFetch' not in the baseline"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "plug/agents/builder.md",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 4},
                    }
                }
            ],
            "properties": {"agent": "builder", "tools": ["WebFetch"]},
        }

    @pytest.mark.parametrize(
        ("severity", "level"), [("high", "error"), ("medium", "warning"), ("low", "note")]
    )
    def test_level_map(self, severity: str, level: str) -> None:
        (result,) = generate_audit_sarif([_row(severity=severity)])["runs"][0]["results"]
        assert result["level"] == level

    def test_python_row_has_no_properties_region_or_context(self) -> None:
        row = _row("SA001", "critical", file_path="app.py", context="sk-secret-value")
        doc = generate_audit_sarif([row])
        (result,) = doc["runs"][0]["results"]
        assert "properties" not in result
        assert "region" not in result["locations"][0]["physicalLocation"]
        assert "sk-secret-value" not in json.dumps(doc)

    def test_absolute_path_under_cwd_is_relative(self, tmp_path: Path) -> None:
        row = _row(file_path=str(tmp_path / "plug" / "agents" / "builder.md"))
        (result,) = generate_audit_sarif([row])["runs"][0]["results"]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc == {"uri": "plug/agents/builder.md", "uriBaseId": "%SRCROOT%"}

    def test_absolute_path_outside_cwd_is_file_uri(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "elsewhere" / "a.md"
        (result,) = generate_audit_sarif([_row(file_path=str(outside))])["runs"][0]["results"]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc == {"uri": outside.as_uri()}

    def test_one_rule_per_id_with_highest_severity(self) -> None:
        rows = [
            _row("CC001", "high", message="first"),
            _row("CC001", "critical", message="second"),
        ]
        run = generate_audit_sarif(rows)["runs"][0]
        (rule,) = run["tool"]["driver"]["rules"]
        assert rule["id"] == "CC001"
        assert rule["shortDescription"] == {"text": "CC001"}
        assert rule["properties"] == {"security-severity": "9.0"}
        assert rule["defaultConfiguration"] == {"level": "error"}
        assert [r["message"]["text"] for r in run["results"]] == ["first", "second"]
        assert [r["level"] for r in run["results"]] == ["error", "error"]

    def test_rules_first_seen_order_and_help(self) -> None:
        rows = [
            _row("SA003", "medium"),
            _row("BL001", "critical", recommendation=""),
            _row("SA003", "low", recommendation="Restrict tools."),
            _row("SA003", "low", recommendation="Other."),
        ]
        rules = generate_audit_sarif(rows)["runs"][0]["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["SA003", "BL001"]
        assert rules[0]["help"] == {"text": "Restrict tools."}
        assert rules[0]["properties"] == {"security-severity": "5.0"}
        assert rules[0]["defaultConfiguration"] == {"level": "warning"}
        assert "help" not in rules[1]
