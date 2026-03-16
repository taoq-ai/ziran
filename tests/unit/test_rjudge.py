"""Tests for R-Judge coverage (GAP-20, issue #59)."""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AttackLibrary

# R-Judge's 10 risk types across 5 application categories.
RJUDGE_RISK_TYPES = [
    "privacy-leakage",
    "computer-security",
    "physical-health",
    "data-loss",
    "financial-loss",
    "property-damage",
    "illegal-activities",
    "ethics-morality",
    "bias-offensiveness",
    "miscellaneous",
]


class TestRJudgeCoverage:
    """GAP-20: Verify R-Judge 10 risk type coverage."""

    @pytest.fixture
    def library(self) -> AttackLibrary:
        return AttackLibrary()

    def test_rjudge_has_10_risk_types(self) -> None:
        assert len(RJUDGE_RISK_TYPES) == 10

    @pytest.mark.parametrize("risk_type", RJUDGE_RISK_TYPES)
    def test_rjudge_risk_type_has_vectors(self, library: AttackLibrary, risk_type: str) -> None:
        """Each R-Judge risk type must have at least one vector tagged rjudge:<type>."""
        tag = f"rjudge:{risk_type}"
        vectors = library.get_attacks_by_tag(tag)
        assert len(vectors) >= 1, f"R-Judge risk type '{risk_type}' has no vectors with tag '{tag}'"

    def test_all_rjudge_vectors_load(self, library: AttackLibrary) -> None:
        """All rjudge-tagged vectors should load without errors."""
        rjudge_vectors = library.get_attacks_by_tag("rjudge")
        assert len(rjudge_vectors) >= 20

    def test_rjudge_multi_turn_tags(self, library: AttackLibrary) -> None:
        """All rjudge-tagged vectors with multiple prompts should have multi_turn tag."""
        rjudge_vectors = library.get_attacks_by_tag("rjudge")
        for v in rjudge_vectors:
            if v.prompt_count > 1:
                assert "multi_turn" in v.tags, (
                    f"R-Judge vector {v.id} has multiple prompts but missing 'multi_turn' tag"
                )
