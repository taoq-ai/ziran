"""Tests for JailbreakBench coverage (GAP-15, issue #54)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AttackCategory

# JailbreakBench's 10 categories aligned with OpenAI usage policies.
JBB_CATEGORIES = [
    "harassment-discrimination",
    "malware-hacking",
    "physical-harm",
    "economic-harm",
    "fraud-deception",
    "disinformation",
    "sexual-adult-content",
    "privacy",
    "expert-advice",
    "government-decision-making",
]


class TestJailbreakBenchCoverage:
    """GAP-15: Verify JailbreakBench 10 category coverage."""

    @pytest.fixture
    def library(self, shared_attack_library: AttackLibrary) -> AttackLibrary:
        return shared_attack_library

    def test_jbb_has_10_categories(self) -> None:
        assert len(JBB_CATEGORIES) == 10

    @pytest.mark.parametrize("category", JBB_CATEGORIES)
    def test_jbb_category_has_vectors(self, library: AttackLibrary, category: str) -> None:
        """Each JBB category must have at least one vector tagged jbb:<category>."""
        tag = f"jbb:{category}"
        vectors = library.get_attacks_by_tag(tag)
        assert len(vectors) >= 1, f"JBB category '{category}' has no vectors with tag '{tag}'"

    def test_prompt_injection_count_gte_100(self, library: AttackLibrary) -> None:
        """Total prompt_injection vectors should be >= 100 for JBB target."""
        pi_vectors = library.get_attacks_by_category(AttackCategory.PROMPT_INJECTION)
        assert len(pi_vectors) >= 100, (
            f"Expected 100+ prompt_injection vectors, got {len(pi_vectors)}"
        )

    def test_all_jbb_tagged_vectors_load(self, library: AttackLibrary) -> None:
        """All jailbreakbench-tagged vectors should load without errors."""
        jbb_vectors = library.get_attacks_by_tag("jailbreakbench")
        assert len(jbb_vectors) >= 36
