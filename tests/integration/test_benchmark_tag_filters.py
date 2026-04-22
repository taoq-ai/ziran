"""Integration tests for the benchmark-expansion tag filters introduced in
spec 012 (US3 and US4). Verifies that the new YAML files are loaded and
discoverable via ``--tag`` filters, and that every vector in each subset
carries both OWASP and ATLAS mappings.
"""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AtlasTechnique


@pytest.mark.integration
@pytest.mark.parametrize(
    "tag",
    ["tensortrust", "wildjailbreak", "toolemu", "cyberseceval", "rag-poisoning"],
)
def test_tag_filter_returns_non_empty_subset(tag: str) -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_tag(tag)
    assert len(vectors) > 0, f"No vectors found for tag '{tag}'"


@pytest.mark.integration
@pytest.mark.parametrize(
    "tag",
    ["tensortrust", "wildjailbreak", "toolemu", "cyberseceval", "rag-poisoning"],
)
def test_tag_filter_vectors_carry_owasp_and_atlas(tag: str) -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_tag(tag)
    for v in vectors:
        assert v.owasp_mapping, f"{v.id} (tag {tag}) missing owasp_mapping"
        assert v.atlas_mapping, f"{v.id} (tag {tag}) missing atlas_mapping"


@pytest.mark.integration
def test_rag_poisoning_vectors_map_to_indirect_injection_and_rag_atlas() -> None:
    lib = AttackLibrary()
    vectors = lib.get_attacks_by_tag("rag-poisoning")
    assert len(vectors) >= 10, "RAG poisoning set should have >= 10 vectors"
    for v in vectors:
        # Every vector carries indirect-injection category
        assert v.category.value == "indirect_injection", (
            f"{v.id} should be category=indirect_injection"
        )
        # Every vector carries an ATLAS indirect-injection technique
        has_indirect = any(
            t in v.atlas_mapping
            for t in (
                AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT,
                AtlasTechnique.RAG_POISONING,
                AtlasTechnique.FALSE_RAG_ENTRY_INJECTION,
                AtlasTechnique.RETRIEVAL_CONTENT_CRAFTING,
                AtlasTechnique.GATHER_RAG_INDEXED_TARGETS,
            )
        )
        assert has_indirect, (
            f"{v.id} must map to at least one RAG/indirect-injection ATLAS technique"
        )
