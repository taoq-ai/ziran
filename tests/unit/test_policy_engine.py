"""Unit tests for the Policy Engine (Feature 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from ziran.application.policy.engine import PolicyEngine
from ziran.domain.entities.attack import (
    AttackCategory,
    AttackResult,
    OwaspLlmCategory,
)
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.entities.policy import (
    Policy,
    PolicyRule,
    PolicyViolation,
    RuleType,
)

if TYPE_CHECKING:
    from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _make_result(
    *,
    successful: bool = True,
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    severity: str = "high",
    owasp: list[OwaspLlmCategory] | None = None,
    vector_id: str = "test_vec",
    vector_name: str = "Test Vector",
) -> dict:
    """Create a serialised AttackResult dict."""
    return AttackResult(
        vector_id=vector_id,
        vector_name=vector_name,
        category=category,
        severity=severity,
        successful=successful,
        evidence={},
        owasp_mapping=owasp or [OwaspLlmCategory.LLM01],
    ).model_dump(mode="json")


def _make_campaign(
    *,
    attack_results: list[dict] | None = None,
    trust_score: float = 0.8,
    critical_paths: list[list[str]] | None = None,
) -> CampaignResult:
    return CampaignResult(
        campaign_id="test_policy",
        target_agent="agent_under_test",
        phases_executed=[],
        attack_results=attack_results or [],
        total_vulnerabilities=sum(1 for r in (attack_results or []) if r.get("successful")),
        final_trust_score=trust_score,
        success=True,
        critical_paths=critical_paths or [],
    )


@pytest.fixture()
def clean_campaign() -> CampaignResult:
    """Campaign with no vulnerabilities and good trust score."""
    return _make_campaign(
        attack_results=[
            _make_result(successful=False),
        ],
        trust_score=0.9,
    )


@pytest.fixture()
def vulnerable_campaign() -> CampaignResult:
    """Campaign with critical and high findings."""
    return _make_campaign(
        attack_results=[
            _make_result(
                successful=True,
                severity="critical",
                category=AttackCategory.PROMPT_INJECTION,
                vector_id="pi_crit",
                vector_name="Critical PI",
            ),
            _make_result(
                successful=True,
                severity="high",
                category=AttackCategory.TOOL_MANIPULATION,
                owasp=[OwaspLlmCategory.LLM07],
                vector_id="tm_high",
                vector_name="Tool Hijack",
            ),
            _make_result(
                successful=True,
                severity="high",
                category=AttackCategory.DATA_EXFILTRATION,
                owasp=[OwaspLlmCategory.LLM06],
                vector_id="de_high",
                vector_name="Data Leak",
            ),
            _make_result(
                successful=True,
                severity="high",
                category=AttackCategory.PRIVILEGE_ESCALATION,
                owasp=[OwaspLlmCategory.LLM08],
                vector_id="pe_high",
                vector_name="Priv Esc",
            ),
        ],
        trust_score=0.3,
        critical_paths=[["a", "b"], ["c", "d"], ["e", "f"], ["g", "h"]],
    )


@pytest.fixture()
def default_engine() -> PolicyEngine:
    return PolicyEngine.default()


# ──────────────────────────────────────────────────────────────────────
# Tests — Policy model
# ──────────────────────────────────────────────────────────────────────


class TestPolicyModels:
    def test_policy_round_trip(self) -> None:
        p = Policy(
            id="test",
            name="Test Policy",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MIN_TRUST_SCORE,
                    parameters={"threshold": 0.5},
                ),
            ],
        )
        data = p.model_dump()
        p2 = Policy.model_validate(data)
        assert p2.id == "test"
        assert len(p2.rules) == 1

    def test_violation_model(self) -> None:
        v = PolicyViolation(
            rule_type=RuleType.MIN_TRUST_SCORE,
            severity="error",
            message="too low",
        )
        assert v.severity == "error"


# ──────────────────────────────────────────────────────────────────────
# Tests — PolicyEngine loading
# ──────────────────────────────────────────────────────────────────────


class TestPolicyEngineLoading:
    def test_default_policy_loads(self, default_engine: PolicyEngine) -> None:
        assert default_engine.policy.id == "ziran-default"
        assert len(default_engine.policy.rules) > 0

    def test_from_yaml(self, tmp_path: Path) -> None:
        policy_data = {
            "id": "custom",
            "name": "Custom Policy",
            "rules": [
                {
                    "rule_type": "min_trust_score",
                    "severity": "error",
                    "parameters": {"threshold": 0.9},
                },
            ],
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy_data))
        engine = PolicyEngine.from_yaml(p)
        assert engine.policy.id == "custom"

    def test_from_yaml_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            PolicyEngine.from_yaml(tmp_path / "missing.yaml")

    def test_from_yaml_invalid(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("just a string")
        with pytest.raises(ValueError, match="expected a mapping"):
            PolicyEngine.from_yaml(p)


# ──────────────────────────────────────────────────────────────────────
# Tests — Rule evaluation
# ──────────────────────────────────────────────────────────────────────


class TestRuleEvaluation:
    def test_clean_campaign_passes_default(
        self,
        default_engine: PolicyEngine,
        clean_campaign: CampaignResult,
    ) -> None:
        verdict = default_engine.evaluate(clean_campaign)
        assert verdict.passed is True
        assert verdict.error_count == 0

    def test_vulnerable_campaign_fails(
        self,
        default_engine: PolicyEngine,
        vulnerable_campaign: CampaignResult,
    ) -> None:
        verdict = default_engine.evaluate(vulnerable_campaign)
        assert verdict.passed is False
        assert verdict.error_count > 0

    def test_min_trust_score_violation(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MIN_TRUST_SCORE,
                    severity="error",
                    parameters={"threshold": 0.8},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(trust_score=0.5)
        verdict = engine.evaluate(campaign)
        assert not verdict.passed
        assert any("0.50" in v.message for v in verdict.violations)

    def test_min_trust_score_pass(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MIN_TRUST_SCORE,
                    severity="error",
                    parameters={"threshold": 0.5},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(trust_score=0.7)
        verdict = engine.evaluate(campaign)
        assert verdict.passed

    def test_max_critical_vulns(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MAX_CRITICAL_VULNS,
                    severity="error",
                    parameters={"threshold": 0},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[_make_result(successful=True, severity="critical")]
        )
        verdict = engine.evaluate(campaign)
        assert not verdict.passed
        assert "1 critical" in verdict.violations[0].message

    def test_max_high_vulns_as_warning(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MAX_HIGH_VULNS,
                    severity="warning",
                    parameters={"threshold": 1},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[
                _make_result(successful=True, severity="high", vector_id="a"),
                _make_result(successful=True, severity="high", vector_id="b"),
            ]
        )
        verdict = engine.evaluate(campaign)
        # warnings don't cause failure
        assert verdict.passed
        assert verdict.warning_count == 1

    def test_max_total_vulns(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MAX_TOTAL_VULNS,
                    severity="error",
                    parameters={"threshold": 2},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[
                _make_result(successful=True, vector_id="a"),
                _make_result(successful=True, vector_id="b"),
                _make_result(successful=True, vector_id="c"),
            ]
        )
        verdict = engine.evaluate(campaign)
        assert not verdict.passed

    def test_required_categories(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.REQUIRED_CATEGORIES,
                    severity="error",
                    parameters={"categories": ["prompt_injection", "tool_manipulation"]},
                )
            ],
        )
        engine = PolicyEngine(policy)
        # Only prompt_injection tested
        campaign = _make_campaign(
            attack_results=[
                _make_result(
                    successful=False,
                    category=AttackCategory.PROMPT_INJECTION,
                )
            ]
        )
        verdict = engine.evaluate(campaign)
        assert not verdict.passed
        assert "tool_manipulation" in verdict.violations[0].message

    def test_required_owasp(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.REQUIRED_OWASP,
                    severity="warning",
                    parameters={"categories": ["LLM01", "LLM02"]},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[
                _make_result(owasp=[OwaspLlmCategory.LLM01]),
            ]
        )
        verdict = engine.evaluate(campaign)
        assert verdict.passed  # only warnings
        assert verdict.warning_count == 1
        assert "LLM02" in verdict.warnings[0].message

    def test_forbidden_findings(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.FORBIDDEN_FINDINGS,
                    severity="error",
                    parameters={
                        "combinations": [{"category": "prompt_injection", "severity": "critical"}]
                    },
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[
                _make_result(
                    successful=True,
                    category=AttackCategory.PROMPT_INJECTION,
                    severity="critical",
                ),
            ]
        )
        verdict = engine.evaluate(campaign)
        assert not verdict.passed
        assert "Forbidden" in verdict.violations[0].message

    def test_forbidden_findings_no_match(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.FORBIDDEN_FINDINGS,
                    severity="error",
                    parameters={
                        "combinations": [{"category": "prompt_injection", "severity": "critical"}]
                    },
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            attack_results=[
                _make_result(
                    successful=True,
                    category=AttackCategory.PROMPT_INJECTION,
                    severity="high",
                ),
            ]
        )
        verdict = engine.evaluate(campaign)
        assert verdict.passed

    def test_max_critical_paths(self) -> None:
        policy = Policy(
            id="t",
            name="T",
            rules=[
                PolicyRule(
                    rule_type=RuleType.MAX_CRITICAL_PATHS,
                    severity="error",
                    parameters={"threshold": 1},
                )
            ],
        )
        engine = PolicyEngine(policy)
        campaign = _make_campaign(
            critical_paths=[["a", "b"], ["c", "d"]],
        )
        verdict = engine.evaluate(campaign)
        assert not verdict.passed

    def test_verdict_summary(
        self,
        default_engine: PolicyEngine,
        clean_campaign: CampaignResult,
    ) -> None:
        verdict = default_engine.evaluate(clean_campaign)
        assert "PASSED" in verdict.summary

    def test_no_rules_always_pass(self) -> None:
        policy = Policy(id="empty", name="Empty", rules=[])
        engine = PolicyEngine(policy)
        campaign = _make_campaign()
        verdict = engine.evaluate(campaign)
        assert verdict.passed
