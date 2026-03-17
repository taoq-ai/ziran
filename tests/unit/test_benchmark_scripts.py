"""Tests for benchmark coverage scripts."""

from __future__ import annotations

from benchmarks.benchmark_comparison import collect_benchmark_comparison
from benchmarks.gap_status import collect_gap_status
from benchmarks.inventory import collect_inventory
from benchmarks.owasp_coverage import collect_owasp_coverage
from ziran.application.attacks.library import AttackLibrary


class TestInventory:
    def test_returns_expected_keys(self) -> None:
        data = collect_inventory()
        assert "total_vectors" in data
        assert "categories" in data
        assert "owasp_distribution" in data
        assert "tactics" in data
        assert "severities" in data
        assert "encoding_types" in data
        assert "unique_tags" in data
        assert "multi_turn_vectors" in data
        assert "business_impact_coverage" in data

    def test_total_matches_library(self) -> None:
        data = collect_inventory()
        library = AttackLibrary()
        assert data["total_vectors"] == len(library.vectors)

    def test_categories_sum_to_total(self) -> None:
        data = collect_inventory()
        assert sum(data["categories"].values()) == data["total_vectors"]

    def test_severities_sum_to_total(self) -> None:
        data = collect_inventory()
        assert sum(data["severities"].values()) == data["total_vectors"]

    def test_tactics_sum_to_total(self) -> None:
        data = collect_inventory()
        assert sum(data["tactics"].values()) == data["total_vectors"]

    def test_encoding_types_positive(self) -> None:
        data = collect_inventory()
        assert data["encoding_types"] >= 8


class TestOwaspCoverage:
    def test_returns_expected_keys(self) -> None:
        data = collect_owasp_coverage()
        assert "covered" in data
        assert "not_covered" in data
        assert "coverage_pct" in data
        assert "per_category" in data
        assert "owasp_categories_total" in data

    def test_all_10_owasp_categories_present(self) -> None:
        data = collect_owasp_coverage()
        assert len(data["per_category"]) == 10

    def test_coverage_pct_is_float(self) -> None:
        data = collect_owasp_coverage()
        assert isinstance(data["coverage_pct"], float)

    def test_covered_plus_not_covered_equals_total(self) -> None:
        data = collect_owasp_coverage()
        assert len(data["covered"]) + len(data["not_covered"]) == data["owasp_categories_total"]

    def test_per_category_has_required_fields(self) -> None:
        data = collect_owasp_coverage()
        for _cat_key, info in data["per_category"].items():
            assert "name" in info
            assert "vectors" in info
            assert "status" in info
            assert info["status"] in ("comprehensive", "strong", "moderate", "planned")


class TestBenchmarkComparison:
    def test_returns_expected_keys(self) -> None:
        data = collect_benchmark_comparison()
        assert "total_benchmarks" in data
        assert "status_summary" in data
        assert "benchmarks" in data

    def test_has_at_least_17_benchmarks(self) -> None:
        data = collect_benchmark_comparison()
        assert data["total_benchmarks"] >= 17

    def test_each_benchmark_has_required_fields(self) -> None:
        data = collect_benchmark_comparison()
        for b in data["benchmarks"]:
            assert "name" in b
            assert "venue" in b
            assert "focus" in b
            assert "gap_status" in b
            assert "metrics" in b
            assert b["gap_status"] in ("closed", "open", "partial", "minimal")

    def test_metrics_have_required_fields(self) -> None:
        data = collect_benchmark_comparison()
        for b in data["benchmarks"]:
            for m in b["metrics"]:
                assert "dimension" in m
                assert "target" in m
                assert "implemented" in m
                assert "pct" in m

    def test_gap_status_matches_canonical_source(self) -> None:
        """Benchmark gap_status must match gap_status.py for benchmarks with gap_id."""
        from benchmarks.gap_status import GAPS

        gap_lookup = {g["id"]: g["status"] for g in GAPS}
        data = collect_benchmark_comparison()
        for b in data["benchmarks"]:
            if b["gap_id"] and b["gap_id"] in gap_lookup:
                assert b["gap_status"] == gap_lookup[b["gap_id"]], (
                    f"{b['name']}: gap_status={b['gap_status']} but "
                    f"{b['gap_id']} is {gap_lookup[b['gap_id']]}"
                )


class TestGapStatus:
    def test_returns_expected_keys(self) -> None:
        data = collect_gap_status()
        assert "gaps" in data
        assert "summary" in data

    def test_has_23_gaps(self) -> None:
        data = collect_gap_status()
        assert data["summary"]["total"] == 23

    def test_each_gap_has_required_fields(self) -> None:
        data = collect_gap_status()
        for gap in data["gaps"]:
            assert "id" in gap
            assert "title" in gap
            assert "priority" in gap
            assert "issue" in gap
            assert "status" in gap
            assert gap["status"] in ("open", "closed", "in_progress")
            assert gap["priority"] in ("critical", "important", "lower")

    def test_summary_has_closure_pct(self) -> None:
        data = collect_gap_status()
        assert "closure_pct" in data["summary"]
        assert isinstance(data["summary"]["closure_pct"], float)
