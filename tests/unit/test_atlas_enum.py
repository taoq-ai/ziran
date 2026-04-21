"""Contract tests for MITRE ATLAS taxonomy embedded in the domain layer.

Mirrors the contract in ``specs/012-benchmark-maturity/contracts/atlas-taxonomy.md``.
"""

from __future__ import annotations

import re

import pytest

from ziran.domain.entities.attack import (
    AGENT_SPECIFIC_TECHNIQUES,
    ATLAS_TACTIC_DESCRIPTIONS,
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_TO_TACTIC,
    AtlasTactic,
    AtlasTechnique,
)


class TestAtlasTacticEnum:
    @pytest.mark.unit
    def test_tactic_values_follow_expected_format(self) -> None:
        pattern = re.compile(r"^AML\.TA\d{4}$")
        for tactic in AtlasTactic:
            assert pattern.match(tactic.value), f"Invalid tactic ID format: {tactic.value}"

    @pytest.mark.unit
    def test_tactic_descriptions_cover_every_enum_member(self) -> None:
        assert set(ATLAS_TACTIC_DESCRIPTIONS) == set(AtlasTactic)

    @pytest.mark.unit
    def test_tactic_count_matches_october_2025_snapshot(self) -> None:
        # October 2025 ATLAS release has 16 tactics. See spec 012 research.md.
        assert len(list(AtlasTactic)) == 16


class TestAtlasTechniqueEnum:
    @pytest.mark.unit
    def test_technique_values_follow_expected_format(self) -> None:
        pattern = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
        for technique in AtlasTechnique:
            assert pattern.match(technique.value), f"Invalid technique ID format: {technique.value}"

    @pytest.mark.unit
    def test_technique_descriptions_cover_every_enum_member(self) -> None:
        assert set(ATLAS_TECHNIQUE_DESCRIPTIONS) == set(AtlasTechnique)

    @pytest.mark.unit
    def test_tactic_map_covers_every_enum_member(self) -> None:
        assert set(ATLAS_TECHNIQUE_TO_TACTIC) == set(AtlasTechnique)

    @pytest.mark.unit
    def test_tactic_map_values_are_valid_tactics(self) -> None:
        for tactics in ATLAS_TECHNIQUE_TO_TACTIC.values():
            assert len(tactics) > 0, "Every technique must belong to at least one tactic"
            for tactic in tactics:
                assert isinstance(tactic, AtlasTactic)

    @pytest.mark.unit
    def test_agent_specific_techniques_has_14_entries(self) -> None:
        # Matches the October 2025 ATLAS release's agent-focused addition count.
        assert len(AGENT_SPECIFIC_TECHNIQUES) == 14

    @pytest.mark.unit
    def test_agent_specific_techniques_subset_of_enum(self) -> None:
        assert AGENT_SPECIFIC_TECHNIQUES.issubset(set(AtlasTechnique))
