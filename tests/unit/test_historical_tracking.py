"""Tests for benchmark historical tracking."""

from __future__ import annotations

import pytest

from benchmarks.historical_tracking import (
    collect_historical_tracking,
    compute_trends,
    take_snapshot,
)


@pytest.mark.unit
class TestHistoricalTracking:
    """Tests for historical tracking and trend analysis."""

    def test_take_snapshot_has_required_fields(self) -> None:
        snapshot = take_snapshot()
        assert "timestamp" in snapshot
        assert "metrics" in snapshot
        metrics = snapshot["metrics"]
        assert "total_vectors" in metrics
        assert "owasp_coverage_pct" in metrics
        assert "categories" in metrics

    def test_snapshot_metrics_positive(self) -> None:
        snapshot = take_snapshot()
        metrics = snapshot["metrics"]
        assert metrics["total_vectors"] > 0
        assert metrics["categories"] > 0
        assert metrics["owasp_coverage_pct"] > 0

    def test_compute_trends_empty_history(self) -> None:
        result = compute_trends([])
        assert result["trend_count"] == 0
        assert result["history_points"] == 0

    def test_compute_trends_single_snapshot(self) -> None:
        snapshot = take_snapshot()
        result = compute_trends([snapshot])
        assert result["history_points"] == 1
        # All deltas should be 0 (comparing against self)
        for trend in result["trends"].values():
            assert trend["delta"] == 0
            assert trend["direction"] == "stable"

    def test_compute_trends_two_snapshots(self) -> None:
        s1 = take_snapshot()
        s2 = take_snapshot()
        # Modify s2 to simulate growth
        s2["metrics"]["total_vectors"] = s1["metrics"]["total_vectors"] + 10
        result = compute_trends([s1, s2])
        assert result["history_points"] == 2
        assert result["trends"]["total_vectors"]["delta"] == 10
        assert result["trends"]["total_vectors"]["direction"] == "up"

    def test_compute_trends_regression(self) -> None:
        s1 = take_snapshot()
        s2 = take_snapshot()
        s2["metrics"]["total_vectors"] = s1["metrics"]["total_vectors"] - 5
        result = compute_trends([s1, s2])
        assert result["trends"]["total_vectors"]["delta"] == -5
        assert result["trends"]["total_vectors"]["direction"] == "down"

    def test_collect_returns_all_sections(self) -> None:
        data = collect_historical_tracking()
        assert "current_snapshot" in data
        assert "trends" in data
        assert "history_count" in data
