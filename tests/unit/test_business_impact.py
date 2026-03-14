"""Unit tests for business impact categorization."""

from __future__ import annotations

from ziran.domain.entities.attack import (
    AttackCategory,
    BusinessImpact,
    get_business_impacts,
)

SEVERITIES = ("low", "medium", "high", "critical")


class TestGetBusinessImpacts:
    """Tests for the get_business_impacts mapping function."""

    def test_all_categories_have_at_least_one_impact(self) -> None:
        for cat in AttackCategory:
            for sev in SEVERITIES:
                impacts = get_business_impacts(cat, sev)
                assert len(impacts) >= 1, f"{cat}/{sev} has no impacts"

    def test_critical_has_at_least_as_many_as_low(self) -> None:
        for cat in AttackCategory:
            low = get_business_impacts(cat, "low")
            critical = get_business_impacts(cat, "critical")
            assert len(critical) >= len(low), (
                f"{cat}: critical ({len(critical)}) < low ({len(low)})"
            )

    def test_returns_business_impact_enums(self) -> None:
        impacts = get_business_impacts(AttackCategory.PROMPT_INJECTION, "medium")
        for imp in impacts:
            assert isinstance(imp, BusinessImpact)

    def test_data_exfiltration_includes_privacy(self) -> None:
        impacts = get_business_impacts(AttackCategory.DATA_EXFILTRATION, "high")
        assert BusinessImpact.PRIVACY_VIOLATION in impacts
        assert BusinessImpact.FINANCIAL_LOSS in impacts

    def test_prompt_injection_critical_adds_system_compromise(self) -> None:
        low = get_business_impacts(AttackCategory.PROMPT_INJECTION, "low")
        crit = get_business_impacts(AttackCategory.PROMPT_INJECTION, "critical")
        assert BusinessImpact.SYSTEM_COMPROMISE not in low
        assert BusinessImpact.SYSTEM_COMPROMISE in crit

    def test_authorization_bypass_high_escalates(self) -> None:
        high = get_business_impacts(AttackCategory.AUTHORIZATION_BYPASS, "high")
        assert BusinessImpact.FINANCIAL_LOSS in high
        assert BusinessImpact.SYSTEM_COMPROMISE in high

    def test_memory_poisoning_includes_misinformation(self) -> None:
        impacts = get_business_impacts(AttackCategory.MEMORY_POISONING, "medium")
        assert BusinessImpact.MISINFORMATION in impacts

    def test_system_prompt_extraction_includes_property_loss(self) -> None:
        impacts = get_business_impacts(AttackCategory.SYSTEM_PROMPT_EXTRACTION, "low")
        assert BusinessImpact.PROPERTY_LOSS in impacts

    def test_no_duplicates(self) -> None:
        for cat in AttackCategory:
            for sev in SEVERITIES:
                impacts = get_business_impacts(cat, sev)
                assert len(impacts) == len(set(impacts)), f"{cat}/{sev} has duplicate impacts"
