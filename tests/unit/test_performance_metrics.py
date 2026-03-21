"""Tests for benchmark performance metrics."""

from __future__ import annotations

from typing import Any

import pytest

from benchmarks.performance_metrics import (
    _measure_operation,
    _summarize_result,
    collect_performance_metrics,
)


@pytest.fixture(scope="module")
def perf_data() -> dict[str, Any]:
    """Run collect_performance_metrics once for all tests in this module."""
    return collect_performance_metrics()


@pytest.mark.unit
class TestPerformanceMetrics:
    """Tests for performance benchmark infrastructure."""

    def test_collect_returns_all_sections(self, perf_data: dict) -> None:
        """Collected metrics should have all required top-level keys."""
        assert "benchmarks" in perf_data
        assert "summary" in perf_data
        assert "targets" in perf_data
        assert "regressions" in perf_data
        assert "regression_detected" in perf_data

    def test_benchmarks_list_nonempty(self, perf_data: dict) -> None:
        """Should have at least one benchmark result."""
        assert len(perf_data["benchmarks"]) >= 5

    def test_benchmark_structure(self, perf_data: dict) -> None:
        """Each benchmark should have timing and memory data."""
        for bench in perf_data["benchmarks"]:
            assert "name" in bench
            assert "timing_seconds" in bench
            assert "memory_bytes" in bench
            t = bench["timing_seconds"]
            assert "min" in t
            assert "max" in t
            assert "mean" in t
            assert t["min"] <= t["mean"] <= t["max"]

    def test_summary_has_throughput(self, perf_data: dict) -> None:
        """Summary should include vector throughput."""
        s = perf_data["summary"]
        assert "vectors_per_second" in s
        assert s["vectors_per_second"] > 0

    def test_targets_defined(self, perf_data: dict) -> None:
        """Performance targets should be defined."""
        targets = perf_data["targets"]
        assert "library_init_max_seconds" in targets
        assert all(v > 0 for v in targets.values())

    def test_no_regressions_on_clean_run(self, perf_data: dict) -> None:
        """A clean run should not detect regressions (generous targets)."""
        assert not perf_data["regression_detected"], (
            f"Unexpected regressions: {perf_data['regressions']}"
        )

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
