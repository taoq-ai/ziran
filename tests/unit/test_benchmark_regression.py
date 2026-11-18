"""Tests for benchmark regression detection."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from benchmarks import regression_check
from benchmarks.regression_check import (
    COMMENT_MARKER,
    _check_regressions,
    _collect_current_metrics,
)

REPO_ROOT = Path(__file__).parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "benchmark.yml"
# A structlog console line: a timestamp, then a bracketed level.
LOG_LINE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T][\d:.]+Z?\s+\[(info|debug|warning)", re.MULTILINE)


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

    def test_comment_file_starts_with_marker_and_holds_no_log_line(self, tmp_path: Path) -> None:
        """Real metrics, as CI runs them: the library logs, the comment file stays clean."""
        comment = tmp_path / "out" / "comment.md"
        proc = subprocess.run(
            [sys.executable, "benchmarks/regression_check.py", "--comment", str(comment)],
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode in (0, 1), proc.stderr
        text = comment.read_text(encoding="utf-8")
        assert text.splitlines()[0] == COMMENT_MARKER
        assert "## Benchmark Coverage Report" in text
        assert LOG_LINE.search(text) is None
        assert "attack_library_initialized" not in text

    def test_regression_still_writes_comment_and_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A regression exits 1 after the comment, with its list, is written."""
        (tmp_path / "baseline.json").write_text(json.dumps(_metrics(700, 99)))
        comment = tmp_path / "comment.md"
        with pytest.raises(SystemExit) as exc:
            _run_main(monkeypatch, tmp_path, _metrics(670, 99), "--comment", str(comment))
        assert exc.value.code == 1
        text = comment.read_text(encoding="utf-8")
        assert text.startswith(COMMENT_MARKER + "\n")
        assert ":x: **Regressions detected:**" in text
        assert "- Total attack vectors decreased: 700 -> 670" in text

    def test_comment_note_follows_delta_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The note names the PR base, or warns that the delta fell back to baseline.json."""
        (tmp_path / "baseline.json").write_text(json.dumps(_metrics(445, 99)))
        delta = tmp_path / "base.json"
        delta.write_text(json.dumps(_metrics(661, 229)))
        comment = tmp_path / "comment.md"

        _run_main(monkeypatch, tmp_path, _metrics(670, 230), "--comment", str(comment))
        text = comment.read_text(encoding="utf-8")
        assert ":warning:" in text
        assert "**Vectors**: +225" in text

        args = ("--comment", str(comment), "--delta-baseline", str(delta))
        _run_main(monkeypatch, tmp_path, _metrics(670, 230), *args)
        text = comment.read_text(encoding="utf-8")
        assert ":warning:" not in text
        assert "relative to the PR base" in text
        assert "**Vectors**: +9" in text

    @pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")
    def test_comment_selector_edits_only_the_bot_marker_comment(self) -> None:
        """The workflow's jq filter must skip a user's comment that copies the marker."""
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["benchmark-comment"][
            "steps"
        ]
        script = next(s["run"] for s in steps if "run" in s)
        match = re.search(r"--jq '([^']+)'", script)
        assert match is not None
        comments = [
            {"id": 111, "user": {"login": "someone"}, "body": f"{COMMENT_MARKER} forged"},
            {"id": 222, "user": {"login": "github-actions[bot]"}, "body": "## Benchmark Coverage"},
            {
                "id": 333,
                "user": {"login": "github-actions[bot]"},
                "body": f"{COMMENT_MARKER}\nreal",
            },
        ]
        out = subprocess.run(
            ["jq", match.group(1)],
            input=json.dumps(comments),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        assert out.stdout.split() == ["333"]

    def test_only_the_comment_job_can_write_and_it_runs_no_repo_code(self) -> None:
        """The job that runs PR code reads only; the writer has no checkout and no uv."""
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        assert workflow["permissions"] == {"contents": "read"}
        writers = [
            name
            for name, job in workflow["jobs"].items()
            if "pull-requests" in job.get("permissions", {})
        ]
        assert writers == ["benchmark-comment"]
        job = workflow["jobs"]["benchmark-comment"]
        assert job["permissions"] == {"pull-requests": "write"}
        for step in job["steps"]:
            assert "checkout" not in step.get("uses", "")
            assert not re.search(r"\b(uv|python)\b", step.get("run", ""))
            assert step.get("continue-on-error") is True
