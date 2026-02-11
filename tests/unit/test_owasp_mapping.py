"""Unit tests for OWASP LLM Top 10 mapping (Feature 4)."""

from __future__ import annotations

import pytest

from koan.application.attacks.library import AttackLibrary
from koan.domain.entities.attack import (
    AttackCategory,
    AttackResult,
    AttackVector,
    OWASP_LLM_DESCRIPTIONS,
    OwaspLlmCategory,
)
from koan.domain.entities.phase import ScanPhase


# ──────────────────────────────────────────────────────────────────────
# OwaspLlmCategory enum
# ──────────────────────────────────────────────────────────────────────


class TestOwaspLlmCategory:
    """Tests for the OWASP LLM Top 10 category enum."""

    def test_all_ten_categories_exist(self) -> None:
        assert len(OwaspLlmCategory) == 10

    def test_values_are_strings(self) -> None:
        for cat in OwaspLlmCategory:
            assert isinstance(cat, str)
            assert cat.startswith("LLM")

    def test_from_string(self) -> None:
        cat = OwaspLlmCategory("LLM01")
        assert cat == OwaspLlmCategory.LLM01

    def test_invalid_category_raises(self) -> None:
        with pytest.raises(ValueError):
            OwaspLlmCategory("LLM99")

    def test_descriptions_complete(self) -> None:
        for cat in OwaspLlmCategory:
            assert cat in OWASP_LLM_DESCRIPTIONS
            assert isinstance(OWASP_LLM_DESCRIPTIONS[cat], str)
            assert len(OWASP_LLM_DESCRIPTIONS[cat]) > 0


# ──────────────────────────────────────────────────────────────────────
# AttackVector / AttackResult owasp_mapping field
# ──────────────────────────────────────────────────────────────────────


class TestOwaspMappingOnModels:
    """Tests for owasp_mapping field on AttackVector and AttackResult."""

    def test_vector_owasp_mapping_default_empty(self) -> None:
        vector = AttackVector(
            id="test_no_owasp",
            name="No OWASP",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="Test",
            severity="low",
        )
        assert vector.owasp_mapping == []

    def test_vector_with_owasp_mapping(self) -> None:
        vector = AttackVector(
            id="test_owasp",
            name="OWASP Mapped",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="Test",
            severity="high",
            owasp_mapping=[OwaspLlmCategory.LLM01],
        )
        assert vector.owasp_mapping == [OwaspLlmCategory.LLM01]

    def test_vector_with_multiple_owasp_categories(self) -> None:
        vector = AttackVector(
            id="test_multi_owasp",
            name="Multi OWASP",
            category=AttackCategory.TOOL_MANIPULATION,
            target_phase=ScanPhase.EXECUTION,
            description="Test",
            severity="critical",
            owasp_mapping=[OwaspLlmCategory.LLM07, OwaspLlmCategory.LLM01],
        )
        assert len(vector.owasp_mapping) == 2
        assert OwaspLlmCategory.LLM07 in vector.owasp_mapping

    def test_result_owasp_mapping_default_empty(self) -> None:
        result = AttackResult(
            vector_id="test",
            vector_name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity="low",
            successful=False,
        )
        assert result.owasp_mapping == []

    def test_result_with_owasp_mapping(self) -> None:
        result = AttackResult(
            vector_id="test",
            vector_name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity="high",
            successful=True,
            owasp_mapping=[OwaspLlmCategory.LLM01],
        )
        assert result.owasp_mapping == [OwaspLlmCategory.LLM01]

    def test_owasp_mapping_serialization(self) -> None:
        vector = AttackVector(
            id="test_serial",
            name="Serialization Test",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="Test",
            severity="medium",
            owasp_mapping=[OwaspLlmCategory.LLM01, OwaspLlmCategory.LLM06],
        )
        data = vector.model_dump(mode="json")
        assert data["owasp_mapping"] == ["LLM01", "LLM06"]


# ──────────────────────────────────────────────────────────────────────
# AttackLibrary OWASP filtering
# ──────────────────────────────────────────────────────────────────────


class TestAttackLibraryOwasp:
    """Tests for OWASP filtering in AttackLibrary."""

    @pytest.fixture
    def library(self) -> AttackLibrary:
        return AttackLibrary()

    def test_all_builtin_vectors_have_owasp_mapping(self, library: AttackLibrary) -> None:
        """Every built-in vector should have at least one OWASP mapping."""
        for vector in library.vectors:
            assert len(vector.owasp_mapping) > 0, (
                f"Vector {vector.id} has no owasp_mapping"
            )

    def test_get_attacks_by_owasp_lmm01(self, library: AttackLibrary) -> None:
        lmm01_attacks = library.get_attacks_by_owasp(OwaspLlmCategory.LLM01)
        assert len(lmm01_attacks) > 0
        for attack in lmm01_attacks:
            assert OwaspLlmCategory.LLM01 in attack.owasp_mapping

    def test_get_attacks_by_owasp_lmm07(self, library: AttackLibrary) -> None:
        lmm07_attacks = library.get_attacks_by_owasp(OwaspLlmCategory.LLM07)
        assert len(lmm07_attacks) > 0
        for attack in lmm07_attacks:
            assert OwaspLlmCategory.LLM07 in attack.owasp_mapping

    def test_prompt_injection_maps_to_lmm01(self, library: AttackLibrary) -> None:
        pi_attacks = library.get_attacks_by_category(AttackCategory.PROMPT_INJECTION)
        for attack in pi_attacks:
            assert OwaspLlmCategory.LLM01 in attack.owasp_mapping

    def test_data_exfiltration_maps_to_lmm02_and_lmm06(
        self, library: AttackLibrary
    ) -> None:
        de_attacks = library.get_attacks_by_category(AttackCategory.DATA_EXFILTRATION)
        for attack in de_attacks:
            assert OwaspLlmCategory.LLM02 in attack.owasp_mapping
            assert OwaspLlmCategory.LLM06 in attack.owasp_mapping

    def test_get_attacks_by_owasp_untested_returns_empty(
        self, library: AttackLibrary
    ) -> None:
        """LLM04 (DoS) and LLM05 (Supply Chain) aren't mapped to any built-in vector."""
        lmm04 = library.get_attacks_by_owasp(OwaspLlmCategory.LLM04)
        assert lmm04 == []

    def test_owasp_mapping_loaded_from_yaml(self, library: AttackLibrary) -> None:
        """Verify a specific vector's OWASP mapping was loaded from YAML."""
        vector = library.get_vector("pi_basic_override")
        assert vector is not None
        assert OwaspLlmCategory.LLM01 in vector.owasp_mapping
