"""Tests for :func:`AttackLibrary.get_attacks_by_atlas` and lint helper.

These tests run against synthetic vectors (not the built-in library) so they
don't depend on how many real vectors happen to be annotated.
"""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import (
    AtlasTechnique,
    AttackCategory,
    AttackPrompt,
    AttackVector,
)
from ziran.domain.entities.phase import ScanPhase


def _make_vector(
    vector_id: str,
    atlas: list[AtlasTechnique] | None = None,
) -> AttackVector:
    return AttackVector(
        id=vector_id,
        name=vector_id.replace("_", " ").title(),
        category=AttackCategory.PROMPT_INJECTION,
        target_phase=ScanPhase.EXECUTION,
        description="synthetic test vector",
        severity="medium",
        prompts=[AttackPrompt(template="test")],
        atlas_mapping=atlas or [],
    )


def _build_library(vectors: list[AttackVector]) -> AttackLibrary:
    """Build a test library from a list of vectors without touching disk."""
    lib = AttackLibrary(load_builtin=False)
    # Test-only: populate the internal registry directly (no public add API).
    for v in vectors:
        lib._vectors[v.id] = v
    lib._rebuild_indices()
    return lib


@pytest.fixture
def library_with_atlas_vectors() -> AttackLibrary:
    """An AttackLibrary with four vectors, three ATLAS-mapped, one not."""
    return _build_library(
        [
            _make_vector("pi_override", [AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT]),
            _make_vector(
                "pi_indirect",
                [
                    AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT,
                    AtlasTechnique.RAG_POISONING,
                ],
            ),
            _make_vector("jailbreak_dan", [AtlasTechnique.LLM_JAILBREAK]),
            _make_vector("unmapped_vector", []),
        ]
    )


class TestGetAttacksByAtlas:
    @pytest.mark.unit
    def test_returns_vectors_with_matching_technique(
        self, library_with_atlas_vectors: AttackLibrary
    ) -> None:
        result = library_with_atlas_vectors.get_attacks_by_atlas(
            AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT
        )
        assert [v.id for v in result] == ["pi_override"]

    @pytest.mark.unit
    def test_returns_vectors_for_multi_mapped_technique(
        self, library_with_atlas_vectors: AttackLibrary
    ) -> None:
        # pi_indirect carries two techniques; both should select it.
        a = library_with_atlas_vectors.get_attacks_by_atlas(
            AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT
        )
        b = library_with_atlas_vectors.get_attacks_by_atlas(AtlasTechnique.RAG_POISONING)
        assert [v.id for v in a] == ["pi_indirect"]
        assert [v.id for v in b] == ["pi_indirect"]

    @pytest.mark.unit
    def test_returns_empty_list_for_unused_technique(
        self, library_with_atlas_vectors: AttackLibrary
    ) -> None:
        result = library_with_atlas_vectors.get_attacks_by_atlas(AtlasTechnique.GENERATE_DEEPFAKES)
        assert result == []

    @pytest.mark.unit
    def test_does_not_return_unmapped_vectors(
        self, library_with_atlas_vectors: AttackLibrary
    ) -> None:
        # Every technique query must exclude unmapped_vector.
        for technique in AtlasTechnique:
            result = library_with_atlas_vectors.get_attacks_by_atlas(technique)
            assert "unmapped_vector" not in [v.id for v in result]


class TestLintAtlasCoverage:
    @pytest.mark.unit
    def test_reports_vectors_with_empty_atlas_mapping(
        self, library_with_atlas_vectors: AttackLibrary
    ) -> None:
        offenders = library_with_atlas_vectors.lint_atlas_coverage()
        assert offenders == ["unmapped_vector"]

    @pytest.mark.unit
    def test_returns_empty_when_all_mapped(self) -> None:
        lib = _build_library(
            [
                _make_vector("a", [AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT]),
                _make_vector("b", [AtlasTechnique.LLM_JAILBREAK]),
            ]
        )
        assert lib.lint_atlas_coverage() == []

    @pytest.mark.unit
    def test_returns_sorted_ids_for_determinism(self) -> None:
        # Add in reverse alphabetical order — helper must emit sorted result.
        lib = _build_library(
            [
                _make_vector("zebra", []),
                _make_vector("alpha", []),
                _make_vector("mango", []),
            ]
        )
        assert lib.lint_atlas_coverage() == ["alpha", "mango", "zebra"]
