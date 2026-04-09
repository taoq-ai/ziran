"""Unit tests for typosquat detection."""

from __future__ import annotations

import pytest

from ziran.application.registry_watch.typosquat_detector import _levenshtein, detect


@pytest.mark.unit
class TestLevenshteinDistance:
    """Tests for the pure-Python Levenshtein implementation."""

    def test_identical_strings(self) -> None:
        assert _levenshtein("weather", "weather") == 0

    def test_single_deletion(self) -> None:
        assert _levenshtein("weather", "weathr") == 1

    def test_single_insertion(self) -> None:
        assert _levenshtein("weather", "weaather") == 1

    def test_single_substitution(self) -> None:
        assert _levenshtein("weather", "weathir") == 1

    def test_transposition_counts_as_two(self) -> None:
        # "weahter" vs "weather" — two operations
        assert _levenshtein("weahter", "weather") == 2

    def test_empty_string(self) -> None:
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3

    def test_both_empty(self) -> None:
        assert _levenshtein("", "") == 0

    def test_completely_different(self) -> None:
        assert _levenshtein("abc", "xyz") == 3


@pytest.mark.unit
class TestDetectTyposquat:
    """Tests for the detect() function."""

    def test_distance_one_flagged_as_high(self) -> None:
        """Names with edit distance 1 should be flagged as high severity."""
        findings = detect("weathr", ["weather"])
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].drift_type == "typosquat"
        assert findings[0].suspected_canonical == "weather"

    def test_distance_two_flagged_as_medium(self) -> None:
        """Names with edit distance 2 should be flagged as medium severity."""
        findings = detect("weahter", ["weather"])
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_distance_three_not_flagged(self) -> None:
        """Names with edit distance > 2 should NOT be flagged."""
        findings = detect("completely-different", ["weather"])
        assert len(findings) == 0

    def test_exact_match_not_flagged(self) -> None:
        """Exact matches should never be flagged."""
        findings = detect("weather", ["weather"])
        assert len(findings) == 0

    def test_substitution_l_to_1(self) -> None:
        """l -> 1 substitution should be detected as high."""
        findings = detect("ca1culator", ["calculator"])
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_substitution_o_to_0(self) -> None:
        """o -> 0 substitution should be detected as high."""
        findings = detect("to0l-server", ["tool-server"])
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_substitution_rn_to_m(self) -> None:
        """rn -> m substitution should be detected as high."""
        findings = detect("leaming-server", ["learning-server"])
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_exemption_list_skips_name(self) -> None:
        """Names in the exemption list should never be flagged."""
        findings = detect("weathr", ["weather"], exemptions=["weathr"])
        assert len(findings) == 0

    def test_multiple_allowlist_entries(self) -> None:
        """A name close to multiple allowlist entries creates findings for each."""
        findings = detect("weathee", ["weather", "weathers"])
        assert len(findings) >= 1

    def test_empty_allowlist(self) -> None:
        """With no allowlist, nothing can be flagged."""
        findings = detect("anything", [])
        assert len(findings) == 0
