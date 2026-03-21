"""Tests for Model DoS (OWASP LLM04) attack vectors."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AttackCategory, OwaspLlmCategory


class TestModelDosCategory:
    def test_model_dos_category_exists(self) -> None:
        assert AttackCategory.MODEL_DOS == "model_dos"


class TestModelDosVectors:
    @pytest.fixture
    def library(self, shared_attack_library: AttackLibrary) -> AttackLibrary:
        return shared_attack_library

    def test_dos_vectors_load(self, library: AttackLibrary) -> None:
        """All model_dos vectors should load without validation errors."""
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        assert len(dos_vectors) >= 12

    def test_all_dos_vectors_map_to_lmm04(self, library: AttackLibrary) -> None:
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            assert OwaspLlmCategory.LLM04 in v.owasp_mapping, (
                f"Vector {v.id} missing LLM04 in owasp_mapping"
            )

    def test_all_dos_vectors_have_model_dos_category(self, library: AttackLibrary) -> None:
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            assert v.category == AttackCategory.MODEL_DOS, (
                f"Vector {v.id} has category {v.category}, expected model_dos"
            )

    def test_all_dos_vectors_have_high_severity(self, library: AttackLibrary) -> None:
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            assert v.severity == "high", f"Vector {v.id} is not high severity"

    def test_all_dos_vectors_have_success_indicators(self, library: AttackLibrary) -> None:
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            has_indicators = any(p.success_indicators for p in v.prompts)
            assert has_indicators, f"Vector {v.id} has no prompts with success_indicators"

    def test_all_dos_vectors_have_dos_tag(self, library: AttackLibrary) -> None:
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            assert "dos" in v.tags, f"Vector {v.id} missing 'dos' tag"
            assert "model_dos" in v.tags, f"Vector {v.id} missing 'model_dos' tag"

    def test_library_get_attacks_by_owasp_lmm04(self, library: AttackLibrary) -> None:
        lmm04_vectors = library.get_attacks_by_owasp(OwaspLlmCategory.LLM04)
        assert len(lmm04_vectors) >= 12

    def test_resource_exhaustion_vectors_exist(self, library: AttackLibrary) -> None:
        re_vectors = [v for v in library.vectors if "resource_exhaustion" in v.tags]
        assert len(re_vectors) >= 3

    def test_long_running_vectors_exist(self, library: AttackLibrary) -> None:
        lr_vectors = [v for v in library.vectors if "long_running" in v.tags]
        assert len(lr_vectors) >= 3

    def test_recursive_vectors_exist(self, library: AttackLibrary) -> None:
        rec_vectors = [v for v in library.vectors if "recursive" in v.tags]
        assert len(rec_vectors) >= 3

    def test_context_flooding_vectors_exist(self, library: AttackLibrary) -> None:
        cf_vectors = [v for v in library.vectors if "context_flooding" in v.tags]
        assert len(cf_vectors) >= 3

    def test_multi_turn_dos_vectors_have_tag(self, library: AttackLibrary) -> None:
        """Multi-turn DoS vectors should have multi_turn tag."""
        dos_vectors = [v for v in library.vectors if v.id.startswith("dos_")]
        for v in dos_vectors:
            if v.tactic and v.tactic != "single":
                assert "multi_turn" in v.tags, (
                    f"Vector {v.id} has tactic {v.tactic} but missing multi_turn tag"
                )
