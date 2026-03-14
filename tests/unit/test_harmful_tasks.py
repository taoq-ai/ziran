"""Tests for harmful multi-step task scenarios and HarmCategory taxonomy."""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import (
    HARM_CATEGORY_DESCRIPTIONS,
    AttackResult,
    AttackVector,
    HarmCategory,
)

# ── HarmCategory enum ────────────────────────────────────────────────


class TestHarmCategory:
    def test_has_11_categories(self) -> None:
        assert len(HarmCategory) == 11

    def test_string_values(self) -> None:
        assert HarmCategory.FRAUD == "fraud"
        assert HarmCategory.CYBERCRIME == "cybercrime"
        assert HarmCategory.HARASSMENT == "harassment"
        assert HarmCategory.DISINFORMATION == "disinformation"
        assert HarmCategory.ILLEGAL_SERVICES == "illegal_services"
        assert HarmCategory.WEAPONS == "weapons"
        assert HarmCategory.SUBSTANCE_ABUSE == "substance_abuse"
        assert HarmCategory.SEXUAL_CONTENT == "sexual_content"
        assert HarmCategory.SELF_HARM == "self_harm"
        assert HarmCategory.TERRORISM == "terrorism"
        assert HarmCategory.CHILD_EXPLOITATION == "child_exploitation"

    def test_all_categories_have_descriptions(self) -> None:
        for cat in HarmCategory:
            assert cat in HARM_CATEGORY_DESCRIPTIONS


# ── Harmful task YAML vectors ────────────────────────────────────────


class TestHarmfulTaskVectors:
    @pytest.fixture
    def library(self) -> AttackLibrary:
        return AttackLibrary()

    def test_harmful_task_vectors_load(self, library: AttackLibrary) -> None:
        """All harmful task vectors should load without validation errors."""
        ht_vectors = [v for v in library.vectors if v.id.startswith("ht_")]
        assert len(ht_vectors) >= 22

    @pytest.mark.parametrize("category", list(HarmCategory))
    def test_each_harm_category_has_vectors(
        self, library: AttackLibrary, category: HarmCategory
    ) -> None:
        vectors = library.get_attacks_by_harm_category(category)
        assert len(vectors) >= 2, f"Harm category {category} has fewer than 2 vectors"

    def test_all_harmful_task_vectors_have_harm_category(self, library: AttackLibrary) -> None:
        ht_vectors = [v for v in library.vectors if v.id.startswith("ht_")]
        for v in ht_vectors:
            assert v.harm_category is not None, f"Vector {v.id} missing harm_category"

    def test_all_harmful_task_vectors_have_success_indicators(self, library: AttackLibrary) -> None:
        ht_vectors = [v for v in library.vectors if v.id.startswith("ht_")]
        for v in ht_vectors:
            has_indicators = any(p.success_indicators for p in v.prompts)
            assert has_indicators, f"Vector {v.id} has no prompts with success_indicators"

    def test_all_harmful_task_vectors_are_critical(self, library: AttackLibrary) -> None:
        ht_vectors = [v for v in library.vectors if v.id.startswith("ht_")]
        for v in ht_vectors:
            assert v.severity == "critical", f"Vector {v.id} is not critical severity"

    def test_library_filter_by_harm_category(self, library: AttackLibrary) -> None:
        fraud_vectors = library.get_attacks_by_harm_category(HarmCategory.FRAUD)
        assert len(fraud_vectors) >= 2
        for v in fraud_vectors:
            assert v.harm_category == HarmCategory.FRAUD


# ── harm_category flows to AttackResult ──────────────────────────────


class TestHarmCategoryInResult:
    def test_harm_category_on_attack_vector(self) -> None:
        vector = AttackVector(
            id="test",
            name="Test",
            category="prompt_injection",
            target_phase="execution",
            description="Test",
            severity="high",
            harm_category=HarmCategory.FRAUD,
        )
        assert vector.harm_category == HarmCategory.FRAUD

    def test_harm_category_default_none(self) -> None:
        vector = AttackVector(
            id="test",
            name="Test",
            category="prompt_injection",
            target_phase="execution",
            description="Test",
            severity="high",
        )
        assert vector.harm_category is None

    def test_harm_category_on_attack_result(self) -> None:
        result = AttackResult(
            vector_id="test",
            vector_name="Test",
            category="prompt_injection",
            severity="high",
            successful=True,
            harm_category=HarmCategory.CYBERCRIME,
        )
        assert result.harm_category == HarmCategory.CYBERCRIME

    def test_harm_category_result_default_none(self) -> None:
        result = AttackResult(
            vector_id="test",
            vector_name="Test",
            category="prompt_injection",
            severity="high",
            successful=False,
        )
        assert result.harm_category is None
