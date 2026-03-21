"""Tests for benchmark performance metrics."""

from __future__ import annotations

import pytest

from benchmarks.performance_metrics import (
    _measure_operation,
    _summarize_result,
    collect_performance_metrics,
)


@pytest.mark.unit
class TestPerformanceMetrics:
    """Tests for performance benchmark infrastructure."""

    def test_collect_returns_all_sections(self) -> None:
        """Collected metrics should have all required top-level keys."""
        data = collect_performance_metrics()
        assert "benchmarks" in data
        assert "summary" in data
        assert "targets" in data
        assert "regressions" in data
        assert "regression_detected" in data

    def test_benchmarks_list_nonempty(self) -> None:
        """Should have at least one benchmark result."""
        data = collect_performance_metrics()
        assert len(data["benchmarks"]) >= 5

    def test_benchmark_structure(self) -> None:
        """Each benchmark should have timing and memory data."""
        data = collect_performance_metrics()
        for bench in data["benchmarks"]:
            assert "name" in bench
            assert "timing_seconds" in bench
            assert "memory_bytes" in bench
            t = bench["timing_seconds"]
            assert "min" in t
            assert "max" in t
            assert "mean" in t
            assert t["min"] <= t["mean"] <= t["max"]

    def test_summary_has_throughput(self) -> None:
        """Summary should include vector throughput."""
        data = collect_performance_metrics()
        s = data["summary"]
        assert "vectors_per_second" in s
        assert s["vectors_per_second"] > 0

    def test_targets_defined(self) -> None:
        """Performance targets should be defined."""
        data = collect_performance_metrics()
        targets = data["targets"]
        assert "library_init_max_seconds" in targets
        assert all(v > 0 for v in targets.values())

    def test_no_regressions_on_clean_run(self) -> None:
        """A clean run should not detect regressions (generous targets)."""
        data = collect_performance_metrics()
        assert not data["regression_detected"], f"Unexpected regressions: {data['regressions']}"

    def test_measure_operation_basic(self) -> None:
        """Measure operation should return valid timing data."""
        result = _measure_operation("test_op", lambda: 42, iterations=2)
        assert result["name"] == "test_op"
        assert result["iterations"] == 2
        assert result["timing_seconds"]["min"] >= 0
        assert result["timing_seconds"]["mean"] >= 0

    def test_summarize_result_dict(self) -> None:
        assert "3 keys" in _summarize_result({"a": 1, "b": 2, "c": 3})

    def test_summarize_result_list(self) -> None:
        assert "2 items" in _summarize_result([1, 2])
