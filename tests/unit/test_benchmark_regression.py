"""Tests for benchmark regression detection."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import pytest

from benchmarks import regression_check
from benchmarks.regression_check import _check_regressions, _collect_current_metrics

if TYPE_CHECKING:
    from pathlib import Path


def _metrics(total_vectors: int, multi_turn_vectors: int) -> dict:
    """Full gate-key metrics dict; only vectors/multi-turn vary between tests."""
    return {
        "total_vectors": total_vectors,
        "categories": 10,
        "owasp_coverage_pct": 100.0,
        "owasp_covered": 10,
        "multi_turn_vectors": multi_turn_vectors,
        "harm_category_count": 5,
        "tactics_count": 8,
    }


def _run_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, current: dict, *argv: str) -> None:
    monkeypatch.setattr(regression_check, "_collect_current_metrics", lambda: current)
    monkeypatch.setattr(regression_check, "BASELINE_PATH", tmp_path / "baseline.json")
    monkeypatch.setattr(sys, "argv", ["regression_check.py", *argv])
    regression_check.main()


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

    def test_delta_uses_passed_metrics_gate_uses_committed_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Changes delta comes from --delta-baseline; the gate uses baseline.json."""
        committed = tmp_path / "baseline.json"
        delta = tmp_path / "base.json"
        committed.write_text(json.dumps(_metrics(445, 99)))
        delta.write_text(json.dumps(_metrics(661, 229)))
        args = ("--format", "markdown", "--delta-baseline", str(delta))

        _run_main(monkeypatch, tmp_path, _metrics(670, 230), *args)
        out = capsys.readouterr().out
        assert "**Changes:** **Vectors**: +9 | **Multi-turn**: +1" in out
        assert "+225" not in out

        committed.write_text(json.dumps(_metrics(700, 99)))
        delta.write_text(json.dumps(_metrics(600, 229)))
        with pytest.raises(SystemExit) as exc:
            _run_main(monkeypatch, tmp_path, _metrics(670, 230), *args)
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert ":x: **Regressions detected:**" in out
        assert "Total attack vectors decreased: 700 -> 670" in out

    def test_delta_defaults_to_committed_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Without the flag the delta is against baseline.json, as before."""
        (tmp_path / "baseline.json").write_text(json.dumps(_metrics(445, 99)))
        _run_main(monkeypatch, tmp_path, _metrics(670, 230), "--format", "markdown")
        assert "**Vectors**: +225 | **Multi-turn**: +131" in capsys.readouterr().out

    def test_unreadable_delta_baseline_is_usage_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A missing or non-JSON --delta-baseline is a usage error (exit 2)."""
        (tmp_path / "baseline.json").write_text(json.dumps(_metrics(445, 99)))
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        for path in (tmp_path / "missing.json", bad):
            with pytest.raises(SystemExit) as exc:
                _run_main(monkeypatch, tmp_path, _metrics(670, 230), "--delta-baseline", str(path))
            assert exc.value.code == 2
            assert "cannot read --delta-baseline" in capsys.readouterr().err
