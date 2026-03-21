"""Unit tests for the AttackLibrary."""

from __future__ import annotations

from pathlib import Path

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AttackCategory
from ziran.domain.entities.phase import ScanPhase


class TestAttackLibrary:
    """Tests for AttackLibrary YAML loading and filtering."""

    @pytest.fixture
    def library(self, shared_attack_library: AttackLibrary) -> AttackLibrary:
        """Library loaded with built-in vectors (session-cached)."""
        return shared_attack_library

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
        recon_attacks = library.get_attacks_for_phase(ScanPhase.RECONNAISSANCE)
        assert len(recon_attacks) >= 1
        for attack in recon_attacks:
            assert attack.target_phase == ScanPhase.RECONNAISSANCE

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
            phase=ScanPhase.RECONNAISSANCE,
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

    def test_indirect_injection_has_50_plus_vectors(self, library: AttackLibrary) -> None:
        """GAP-02: indirect_injection category should have 50+ vectors."""
        ii_attacks = library.get_attacks_by_category(AttackCategory.INDIRECT_INJECTION)
        assert len(ii_attacks) >= 50, (
            f"Expected 50+ indirect injection vectors, got {len(ii_attacks)}"
        )

    def test_no_duplicate_ids_across_files(self, library: AttackLibrary) -> None:
        """All vector IDs must be unique across all YAML files."""
        seen: dict[str, str] = {}
        for vector in library.vectors:
            assert vector.id not in seen, (
                f"Duplicate vector ID '{vector.id}' (first in category "
                f"'{seen[vector.id]}', duplicate in '{vector.category}')"
            )
            seen[vector.id] = str(vector.category)

    def test_agentharm_multistep_coverage(self, library: AttackLibrary) -> None:
        """Issue #131: AgentHarm expansion should provide 100+ multi-step vectors."""
        harm_vectors = [v for v in library.vectors if getattr(v, "harm_category", None) is not None]
        assert len(harm_vectors) >= 100, (
            f"Expected 100+ harm-category vectors, got {len(harm_vectors)}"
        )

    def test_agentharm_all_categories_covered(self, library: AttackLibrary) -> None:
        """Issue #131: All 11 AgentHarm harm categories should have vectors."""
        from ziran.domain.entities.attack import HarmCategory

        harm_vectors = [v for v in library.vectors if getattr(v, "harm_category", None) is not None]
        covered = {v.harm_category for v in harm_vectors}
        expected = set(HarmCategory)
        missing = expected - covered
        assert not missing, f"Missing harm categories: {missing}"

    def test_agentharm_tactic_diversity(self, library: AttackLibrary) -> None:
        """Issue #131: Expanded vectors should use diverse multi-turn tactics."""
        harm_vectors = [v for v in library.vectors if getattr(v, "harm_category", None) is not None]
        tactics = {v.tactic for v in harm_vectors if v.tactic}
        assert len(tactics) >= 5, (
            f"Expected 5+ distinct tactics in harm vectors, got {len(tactics)}: {tactics}"
        )

    def test_mcp_vectors_loaded(self, library: AttackLibrary) -> None:
        """GAP-03: MCP tool poisoning vectors should be loaded."""
        mcp_attacks = [v for v in library.vectors if "mcp" in v.protocol_filter]
        assert len(mcp_attacks) >= 10, f"Expected 10+ MCP vectors, got {len(mcp_attacks)}"

    def test_mcptox_expanded_coverage(self, library: AttackLibrary) -> None:
        """Issue #146: MCPTox expansion should provide 100+ MCP vectors."""
        mcp_attacks = library.get_attacks_by_tag("mcp")
        assert len(mcp_attacks) >= 100, (
            f"Expected 100+ MCP vectors for MCPTox coverage, got {len(mcp_attacks)}"
        )

    def test_mcptox_category_diversity(self, library: AttackLibrary) -> None:
        """Issue #146: MCPTox vectors should span multiple attack categories."""
        mcptox = library.get_attacks_by_tag("mcptox")
        categories = {v.category for v in mcptox}
        assert len(categories) >= 3, (
            f"Expected MCPTox vectors in 3+ categories, got {len(categories)}: {categories}"
        )

    def test_mcp_vectors_have_protocol_filter(self, library: AttackLibrary) -> None:
        """All MCP vectors should have protocol_filter=['mcp']."""
        mcp_attacks = [v for v in library.vectors if v.id.startswith("mcp_")]
        assert len(mcp_attacks) > 0
        for v in mcp_attacks:
            assert "mcp" in v.protocol_filter, (
                f"MCP vector '{v.id}' missing protocol_filter=['mcp']"
            )


class TestLoadErrorTracking:
    """Tests for load error tracking (#126)."""

    def test_load_errors_empty_for_valid_files(self) -> None:
        """Built-in library should have zero load errors."""
        lib = AttackLibrary()
        assert lib.load_error_count == 0
        assert lib.load_errors == []

    def test_load_errors_tracked_for_invalid_vector(self, tmp_path: Path) -> None:
        """One valid + one invalid vector → error count 1, vector count 1."""
        yaml_content = """
vectors:
  - id: good_vector
    name: Good Vector
    category: prompt_injection
    target_phase: reconnaissance
    severity: low
    description: Valid vector
    prompts:
      - template: "Test"
        success_indicators: ["ok"]
  - id: bad_vector
    name: Bad Vector
    category: INVALID_CATEGORY
    target_phase: reconnaissance
    severity: low
    description: Invalid category
    prompts:
      - template: "Test"
        success_indicators: ["ok"]
"""
        (tmp_path / "mixed.yaml").write_text(yaml_content)
        lib = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)
        assert lib.vector_count == 1
        assert lib.load_error_count == 1
        assert lib.load_errors[0][0] == "bad_vector"

    def test_load_errors_for_bad_yaml_file(self, tmp_path: Path) -> None:
        """Malformed YAML should be tracked as a load error."""
        (tmp_path / "broken.yaml").write_text("{{invalid yaml: [")
        lib = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)
        assert lib.vector_count == 0
        assert lib.load_error_count == 1
