"""Unit tests for the AttackLibrary."""

from __future__ import annotations

from pathlib import Path

import pytest

from koan.application.attacks.library import AttackLibrary
from koan.domain.entities.attack import AttackCategory
from koan.domain.entities.phase import RomanceScanPhase


class TestAttackLibrary:
    """Tests for AttackLibrary YAML loading and filtering."""

    @pytest.fixture
    def library(self) -> AttackLibrary:
        """Library loaded with built-in vectors."""
        return AttackLibrary()

    def test_loads_builtin_vectors(self, library: AttackLibrary) -> None:
        assert library.vector_count > 0

    def test_all_categories_present(self, library: AttackLibrary) -> None:
        categories = library.categories
        # We defined 8 YAML files, each with a different category
        assert len(categories) >= 7

    def test_get_vector_by_id(self, library: AttackLibrary) -> None:
        vector = library.get_vector("pi_basic_override")
        assert vector is not None
        assert vector.name == "Basic Instruction Override"
        assert vector.category == AttackCategory.PROMPT_INJECTION

    def test_get_nonexistent_vector(self, library: AttackLibrary) -> None:
        assert library.get_vector("nonexistent_id") is None

    def test_get_attacks_for_phase(self, library: AttackLibrary) -> None:
        recon_attacks = library.get_attacks_for_phase(RomanceScanPhase.RECONNAISSANCE)
        assert len(recon_attacks) >= 1
        for attack in recon_attacks:
            assert attack.target_phase == RomanceScanPhase.RECONNAISSANCE

    def test_get_attacks_by_category(self, library: AttackLibrary) -> None:
        pi_attacks = library.get_attacks_by_category(AttackCategory.PROMPT_INJECTION)
        assert len(pi_attacks) >= 1
        for attack in pi_attacks:
            assert attack.category == AttackCategory.PROMPT_INJECTION

    def test_get_attacks_by_severity(self, library: AttackLibrary) -> None:
        critical_attacks = library.get_attacks_by_severity("critical")
        assert len(critical_attacks) >= 1
        for attack in critical_attacks:
            assert attack.severity == "critical"

    def test_get_attacks_by_tag(self, library: AttackLibrary) -> None:
        tagged = library.get_attacks_by_tag("prompt_injection")
        assert len(tagged) >= 1
        for attack in tagged:
            assert "prompt_injection" in attack.tags

    def test_search_with_multiple_filters(self, library: AttackLibrary) -> None:
        results = library.search(
            category=AttackCategory.PROMPT_INJECTION,
            severity="high",
        )
        for attack in results:
            assert attack.category == AttackCategory.PROMPT_INJECTION
            assert attack.severity == "high"

    def test_search_with_no_results(self, library: AttackLibrary) -> None:
        results = library.search(
            phase=RomanceScanPhase.RECONNAISSANCE,
            severity="critical",
            tags=["nonexistent_tag_xyz"],
        )
        assert results == []

    def test_all_vectors_have_ids(self, library: AttackLibrary) -> None:
        for vector in library.vectors:
            assert vector.id, f"Vector missing ID: {vector.name}"
            assert vector.name, f"Vector missing name: {vector.id}"

    def test_all_vectors_have_valid_severity(self, library: AttackLibrary) -> None:
        valid_severities = {"low", "medium", "high", "critical"}
        for vector in library.vectors:
            assert vector.severity in valid_severities, (
                f"Invalid severity '{vector.severity}' for vector {vector.id}"
            )

    def test_all_vectors_have_prompts(self, library: AttackLibrary) -> None:
        for vector in library.vectors:
            assert vector.prompt_count > 0, f"Vector {vector.id} has no prompts"

    def test_no_builtin_loading(self) -> None:
        lib = AttackLibrary(load_builtin=False)
        assert lib.vector_count == 0

    def test_custom_directory(self, tmp_path: Path) -> None:
        # Create a custom YAML file
        yaml_content = """
vectors:
  - id: custom_test
    name: Custom Test Vector
    category: prompt_injection
    target_phase: reconnaissance
    severity: low
    description: A custom test vector
    prompts:
      - template: "Test {var}"
        variables:
          var: "value"
        success_indicators: ["success"]
"""
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text(yaml_content)

        lib = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)
        assert lib.vector_count == 1
        assert lib.get_vector("custom_test") is not None

    def test_custom_merged_with_builtin(self, tmp_path: Path) -> None:
        yaml_content = """
vectors:
  - id: custom_extra
    name: Extra Vector
    category: prompt_injection
    target_phase: execution
    severity: medium
    description: An extra test vector
    prompts:
      - template: "Extra test"
        success_indicators: ["ok"]
"""
        yaml_file = tmp_path / "extra.yaml"
        yaml_file.write_text(yaml_content)

        lib = AttackLibrary(custom_dirs=[tmp_path], load_builtin=True)
        builtin_lib = AttackLibrary()
        assert lib.vector_count == builtin_lib.vector_count + 1
        assert lib.get_vector("custom_extra") is not None

    def test_nonexistent_directory(self) -> None:
        # Should not raise, just log a warning
        lib = AttackLibrary(
            custom_dirs=[Path("/nonexistent/path")],
            load_builtin=False,
        )
        assert lib.vector_count == 0
