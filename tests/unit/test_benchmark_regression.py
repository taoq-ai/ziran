"""Tests for benchmark regression detection."""

from __future__ import annotations

import pytest

from benchmarks.regression_check import _check_regressions, _collect_current_metrics


@pytest.mark.unit
class TestBenchmarkRegression:
    """Tests for benchmark regression detection."""

    def test_collect_current_metrics(self) -> None:
        """Collecting metrics should return expected structure."""
        metrics = _collect_current_metrics()
        assert metrics["total_vectors"] > 0
        assert metrics["categories"] > 0
        assert metrics["owasp_coverage_pct"] > 0
        assert metrics["harm_category_count"] > 0
        assert "benchmark_details" in metrics

    def test_no_regression_when_metrics_improve(self) -> None:
        """No regression when current metrics are higher than baseline."""
        baseline = {"total_vectors": 100, "categories": 5, "owasp_covered": 8}
        current = {"total_vectors": 200, "categories": 10, "owasp_covered": 9}
        regressions = _check_regressions(current, baseline)
        assert regressions == []

    def test_no_regression_when_equal(self) -> None:
        """No regression when metrics are unchanged."""
        baseline = {"total_vectors": 100, "owasp_coverage_pct": 80.0}
        current = {"total_vectors": 100, "owasp_coverage_pct": 80.0}
        regressions = _check_regressions(current, baseline)
        assert regressions == []

    def test_regression_detected_on_vector_drop(self) -> None:
        """Regression detected when total vectors decrease."""
        baseline = {"total_vectors": 200}
        current = {"total_vectors": 150}
        regressions = _check_regressions(current, baseline)
        assert len(regressions) == 1
        assert "decreased" in regressions[0]

    def test_regression_detected_on_owasp_drop(self) -> None:
        """Regression detected when OWASP coverage drops."""
        baseline = {"owasp_coverage_pct": 90.0}
        current = {"owasp_coverage_pct": 80.0}
        regressions = _check_regressions(current, baseline)
        assert len(regressions) == 1
        assert "OWASP" in regressions[0]

    def test_multiple_regressions(self) -> None:
        """Multiple regressions detected simultaneously."""
        baseline = {
            "total_vectors": 200,
            "categories": 10,
            "owasp_coverage_pct": 90.0,
        }
        current = {
            "total_vectors": 100,
            "categories": 5,
            "owasp_coverage_pct": 70.0,
        }
        regressions = _check_regressions(current, baseline)
        assert len(regressions) == 3
