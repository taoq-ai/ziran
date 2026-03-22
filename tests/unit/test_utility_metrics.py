"""Tests for benchmark utility-under-attack metrics."""

from __future__ import annotations

import pytest

from benchmarks.utility_metrics import (
    _count_multi_turn_vectors,
    _count_utility_capable_vectors,
    collect_utility_metrics,
)
from ziran.application.attacks.library import AttackLibrary


@pytest.mark.unit
class TestUtilityMetrics:
    """Tests for utility-under-attack aggregate metrics."""

    def test_collect_returns_all_sections(self) -> None:
        """Collected metrics should have all required top-level keys."""
        data = collect_utility_metrics()
        assert "capabilities" in data
        assert "capability_count" in data
        assert "capability_total" in data
        assert "model_fields" in data
        assert "agentdojo_alignment" in data
        assert "asb_alignment" in data
        assert "vector_coverage" in data
        assert "implementation_status" in data

    def test_all_capabilities_enabled(self) -> None:
        """All utility measurement capabilities should be enabled."""
        data = collect_utility_metrics()
        assert data["capability_count"] == data["capability_total"]
        for cap, enabled in data["capabilities"].items():
            assert enabled, f"Capability '{cap}' is not enabled"

    def test_agentdojo_alignment_metrics(self) -> None:
        """AgentDojo alignment should include required metrics."""
        data = collect_utility_metrics()
        alignment = data["agentdojo_alignment"]
        assert alignment["task_success_rate"] is True
        assert alignment["utility_degradation"] is True
        assert alignment["per_task_breakdown"] is True
        assert alignment["indirect_injection_vectors"] > 0

    def test_asb_alignment_metrics(self) -> None:
        """ASB alignment should include required metrics."""
        data = collect_utility_metrics()
        alignment = data["asb_alignment"]
        assert alignment["pre_attack_utility"] is True
        assert alignment["post_attack_utility"] is True
        assert alignment["utility_delta"] is True
        assert alignment["multi_scenario_support"] is True
        assert alignment["attack_categories"] >= 5

    def test_model_fields_include_utility_metrics(self) -> None:
        """Model fields should include core UtilityMetrics fields."""
        data = collect_utility_metrics()
        fields = data["model_fields"]["utility_metrics"]
        assert "baseline_score" in fields
        assert "post_attack_score" in fields
        assert "utility_delta" in fields
        assert "tasks_run" in fields

    def test_model_fields_include_utility_task(self) -> None:
        """Model fields should include core UtilityTask fields."""
        data = collect_utility_metrics()
        fields = data["model_fields"]["utility_task"]
        assert "id" in fields
        assert "prompt" in fields
        assert "success_indicators" in fields

    def test_vector_coverage_positive(self) -> None:
        """Vector coverage counts should be positive."""
        data = collect_utility_metrics()
        vecs = data["vector_coverage"]
        assert vecs["total_vectors"] > 0
        assert vecs["utility_testable_vectors"] > 0
        assert vecs["multi_turn_vectors"] > 0

    def test_implementation_status_all_complete(self) -> None:
        """All implementation components should be complete."""
        data = collect_utility_metrics()
        for component, status in data["implementation_status"].items():
            assert status == "complete", f"Component '{component}' is '{status}'"

    def test_count_utility_capable_vectors(self) -> None:
        """Should count vectors with success/failure indicators."""
        lib = AttackLibrary()
        count = _count_utility_capable_vectors(lib)
        assert count > 0
        assert count <= len(lib.vectors)

    def test_count_multi_turn_vectors(self) -> None:
        """Should count vectors with non-single tactics."""
        lib = AttackLibrary()
        count = _count_multi_turn_vectors(lib)
        assert count > 0
        assert count < len(lib.vectors)
