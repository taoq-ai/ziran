"""Tests for benchmark accuracy metrics."""

from __future__ import annotations

import pytest

from benchmarks.accuracy_metrics import (
    _load_scenarios,
    _wilson_ci,
    collect_accuracy_metrics,
)


@pytest.mark.unit
class TestAccuracyMetrics:
    """Tests for precision, recall, and F1 metrics."""

    def test_load_scenarios(self) -> None:
        """Ground truth scenarios should load from YAML."""
        scenarios = _load_scenarios()
        assert len(scenarios) > 0
        for s in scenarios:
            assert s.scenario_id
            assert s.ground_truth.label in ("true_positive", "true_negative")

    def test_overall_metrics_structure(self) -> None:
        """Overall metrics should have expected fields."""
        data = collect_accuracy_metrics()
        overall = data["overall"]
        assert "total_scenarios" in overall
        assert "true_positives" in overall
        assert "true_negatives" in overall
        assert "attack_success_rate" in overall
        assert "dataset_balance" in overall
        assert "tp_confidence_interval" in overall
        assert "theoretical_perfect_detection" in overall

    def test_tp_plus_tn_equals_total(self) -> None:
        """TP + TN should equal total scenarios."""
        data = collect_accuracy_metrics()
        overall = data["overall"]
        assert overall["true_positives"] + overall["true_negatives"] == overall["total_scenarios"]

    def test_by_category_nonempty(self) -> None:
        """Per-category breakdown should have at least one category."""
        data = collect_accuracy_metrics()
        assert len(data["by_category"]) > 0

    def test_by_severity_nonempty(self) -> None:
        """Per-severity breakdown should have at least one level."""
        data = collect_accuracy_metrics()
        assert len(data["by_severity"]) > 0

    def test_detector_coverage_nonempty(self) -> None:
        """Detector coverage should report on at least one detector."""
        data = collect_accuracy_metrics()
        assert len(data["detector_coverage"]) > 0

    def test_wilson_ci_basic(self) -> None:
        """Wilson CI should return reasonable bounds."""
        lower, upper = _wilson_ci(50, 100)
        assert 0.35 < lower < 0.45
        assert 0.55 < upper < 0.65

    def test_wilson_ci_zero_total(self) -> None:
        """Wilson CI with zero total should return (0, 0)."""
        assert _wilson_ci(0, 0) == (0.0, 0.0)

    def test_wilson_ci_all_successes(self) -> None:
        """Wilson CI with all successes should have upper near 1."""
        _lower, upper = _wilson_ci(100, 100)
        assert upper > 0.95

    def test_asr_between_zero_and_one(self) -> None:
        """Attack success rate should be between 0 and 1."""
        data = collect_accuracy_metrics()
        asr = data["overall"]["attack_success_rate"]
        assert 0.0 <= asr <= 1.0

    def test_dataset_balance_positive(self) -> None:
        """Dataset balance should be positive (TP and TN both exist)."""
        data = collect_accuracy_metrics()
        assert data["overall"]["dataset_balance"] > 0
