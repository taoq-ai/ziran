"""Integration test for OWASP LLM Top 10 full coverage after spec 012.

After the Benchmark Maturity release, every OWASP LLM category must be at
"strong" (>= 10 vectors) or "comprehensive" — closing the LLM05 and LLM10
gaps (issues #42, #43). Every new vector must carry both OWASP and ATLAS
mappings.
"""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import OwaspLlmCategory


@pytest.mark.integration
def test_every_owasp_category_has_at_least_ten_vectors() -> None:
    lib = AttackLibrary()
    for cat in OwaspLlmCategory:
        vectors = lib.get_attacks_by_owasp(cat)
        assert len(vectors) >= 10, (
            f"OWASP {cat.value} has only {len(vectors)} vectors; "
            f"spec 012 requires >= 10 (strong) across all categories."
        )


@pytest.mark.integration
def test_llm05_supply_chain_specific_vectors_present() -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_owasp(OwaspLlmCategory.LLM05)
    ids = {v.id for v in vectors}
    # Spot-check: the supply_chain.yaml vectors must be present.
    assert "sc_typosquatted_tool" in ids
    assert "sc_dependency_confusion" in ids
    assert "sc_compromised_model_weights" in ids


@pytest.mark.integration
def test_llm10_model_theft_specific_vectors_present() -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_owasp(OwaspLlmCategory.LLM10)
    ids = {v.id for v in vectors}
    # Spot-check: the model_theft.yaml vectors must be present.
    assert "mt_systematic_extraction" in ids
    assert "mt_membership_inference" in ids
    assert "mt_model_fingerprinting" in ids


@pytest.mark.integration
def test_every_supply_chain_vector_carries_atlas_mapping() -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_owasp(OwaspLlmCategory.LLM05)
    for v in vectors:
        assert v.atlas_mapping, (
            f"Vector {v.id} in LLM05 must carry an ATLAS mapping "
            "(spec 012 requires every new vector carry both)."
        )


@pytest.mark.integration
def test_every_model_theft_vector_carries_atlas_mapping() -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_owasp(OwaspLlmCategory.LLM10)
    for v in vectors:
        assert v.atlas_mapping, (
            f"Vector {v.id} in LLM10 must carry an ATLAS mapping "
            "(spec 012 requires every new vector carry both)."
        )
