"""Tests for benchmark comparative analysis."""

from __future__ import annotations

import pytest

from benchmarks.comparative_analysis import (
    CAPABILITY_MATRIX,
    TOOLS,
    _score_to_value,
    collect_comparative_analysis,
    generate_markdown,
)


@pytest.mark.unit
class TestComparativeAnalysis:
    """Tests for comparative analysis against other tools."""

    def test_collect_returns_all_sections(self) -> None:
        data = collect_comparative_analysis()
        assert "tools" in data
        assert "capability_count" in data
        assert "ziran_strengths" in data
        assert "ziran_gaps" in data
        assert "ziran_unique_strengths" in data
        assert "competitive_gaps" in data
        assert "ranking" in data

    def test_all_tools_present(self) -> None:
        data = collect_comparative_analysis()
        tool_names = {t["name"] for t in TOOLS}
        assert tool_names == set(data["tools"].keys())

    def test_ziran_has_unique_strengths(self) -> None:
        """ZIRAN should have capabilities no other tool has."""
        data = collect_comparative_analysis()
        assert len(data["ziran_unique_strengths"]) >= 3

    def test_ranking_ordered_by_score(self) -> None:
        data = collect_comparative_analysis()
        scores = [score for _, score in data["ranking"]]
        assert scores == sorted(scores, reverse=True)

    def test_capability_matrix_consistent(self) -> None:
        """Every capability must have an entry for every tool."""
        tool_names = {t["name"] for t in TOOLS}
        for cap, scores in CAPABILITY_MATRIX.items():
            assert set(scores.keys()) == tool_names, f"Mismatch in '{cap}'"

    def test_score_to_value(self) -> None:
        assert _score_to_value("full") == 1.0
        assert _score_to_value("partial") == 0.5
        assert _score_to_value("none") == 0.0
        assert _score_to_value("unknown") == 0.0

    def test_ziran_vector_count_positive(self) -> None:
        data = collect_comparative_analysis()
        assert data["ziran_vector_count"] > 0

    def test_generate_markdown_contains_table(self) -> None:
        data = collect_comparative_analysis()
        md = generate_markdown(data)
        assert "| Capability |" in md
        assert "ZIRAN" in md
        assert "Promptfoo" in md

    def test_tool_coverage_pct_valid(self) -> None:
        data = collect_comparative_analysis()
        for name, tool in data["tools"].items():
            assert 0 <= tool["coverage_pct"] <= 100, f"{name} coverage out of range"
