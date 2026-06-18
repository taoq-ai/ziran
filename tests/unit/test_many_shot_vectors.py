"""Unit tests for the many-shot vector library (spec 023, T010)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ziran.application.attacks.many_shot import ShotRenderer
from ziran.domain.entities.attack import AtlasTechnique, OwaspLlmCategory

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit


def _many_shot_vectors(shared_attack_library: AttackLibrary) -> list:
    return [v for v in shared_attack_library.vectors if v.many_shot is not None]


def test_at_least_ten_vectors_across_harms(shared_attack_library: AttackLibrary) -> None:
    ms = _many_shot_vectors(shared_attack_library)
    assert len(ms) >= 10  # SC-001
    harms = {v.harm_category.value for v in ms if v.harm_category}
    assert len(harms) >= 3


def test_taxonomy_owasp_and_atlas(shared_attack_library: AttackLibrary) -> None:
    for v in _many_shot_vectors(shared_attack_library):
        assert OwaspLlmCategory.LLM01 in v.owasp_mapping  # FR-005
        assert AtlasTechnique.LLM_JAILBREAK in v.atlas_mapping  # AML.T0054
        assert AtlasTechnique.LLM_PROMPT_CRAFTING in v.atlas_mapping  # AML.T0065
        assert "many-shot" in v.tags  # FR-009 tag


def test_every_corpus_key_exists(shared_attack_library: AttackLibrary) -> None:
    """Vector↔corpus cross-check (moved here from the corpus test — F3)."""
    available = ShotRenderer().available_keys()
    for v in _many_shot_vectors(shared_attack_library):
        assert v.many_shot.corpus in available, (
            f"vector {v.id} references missing corpus key {v.many_shot.corpus}"
        )
