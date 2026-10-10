"""Tests for scripts/sample_crewai_units.py (spec 056)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sample_crewai_units.py"


def _unit(i: int, errors: bool = False) -> dict[str, Any]:
    return {
        "agent": f"agent{i:03d}",
        "file": f"repo{i % 7}/config/agents.yaml",
        "line": 1,
        "tools": [f"T{i}", "send_email"],
        "agent_tools": [f"T{i}"],
        "tasks": [{"name": "t", "tools": ["send_email"]}],
        "errors": [{"file": "crew.py", "line": 1, "message": "invalid Python syntax"}]
        if errors
        else [],
    }


def _run(doc: object, tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _sampled(stdout: str) -> list[str]:
    return [line.split()[1] for line in stdout.splitlines() if line.startswith("unit ")]


@pytest.mark.unit
class TestSampleCrewAIUnits:
    def test_same_seed_same_sample(self, tmp_path: Path) -> None:
        doc = {"crewai": [_unit(i) for i in range(120)]}
        first = _run(doc, tmp_path, "--seed", "7", "--n", "50")
        second = _run(doc, tmp_path, "--seed", "7", "--n", "50")
        assert first.returncode == 0, first.stderr
        assert first.stdout == second.stdout
        assert len(set(_sampled(first.stdout))) == 50
        assert "seed=7 n=50 frame=120 left_out_with_errors=0" in first.stdout
        assert "agent_tools: T" in first.stdout
        assert "task t: send_email" in first.stdout

    def test_other_seed_other_sample(self, tmp_path: Path) -> None:
        doc = {"crewai": [_unit(i) for i in range(120)]}
        a = _sampled(_run(doc, tmp_path, "--seed", "7").stdout)
        b = _sampled(_run(doc, tmp_path, "--seed", "8").stdout)
        assert len(a) == 50 and a != b

    def test_sample_ignores_input_order(self, tmp_path: Path) -> None:
        units = [_unit(i) for i in range(80)]
        a = _run({"crewai": units}, tmp_path, "--seed", "3").stdout
        b = _run({"crewai": units[::-1]}, tmp_path, "--seed", "3").stdout
        assert a == b

    def test_fewer_units_than_n(self, tmp_path: Path) -> None:
        result = _run({"crewai": [_unit(i) for i in range(5)]}, tmp_path, "--seed", "1")
        assert len(_sampled(result.stdout)) == 5

    def test_errored_units_left_out(self, tmp_path: Path) -> None:
        units = [_unit(i, errors=i % 2 == 0) for i in range(10)]
        result = _run({"crewai": units}, tmp_path, "--seed", "1")
        assert "frame=5 left_out_with_errors=5" in result.stdout
        assert all(int(name[-3:]) % 2 == 1 for name in _sampled(result.stdout))

    @pytest.mark.parametrize("doc", [{"findings": []}, {"crewai": "x"}, [1]])
    def test_missing_crewai_list_exits_2(self, tmp_path: Path, doc: object) -> None:
        result = _run(doc, tmp_path, "--seed", "1")
        assert result.returncode == 2
        assert "has no crewai list" in result.stderr

    def test_unreadable_file_exits_2(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(tmp_path / "missing.json"), "--seed", "1"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "cannot read" in result.stderr

    def test_seed_is_required(self, tmp_path: Path) -> None:
        assert _run({"crewai": []}, tmp_path).returncode == 2

    @pytest.mark.parametrize("n", ["0", "-1"])
    def test_n_below_one_exits_2(self, tmp_path: Path, n: str) -> None:
        result = _run({"crewai": [_unit(1)]}, tmp_path, "--seed", "1", "--n", n)
        assert result.returncode == 2
        assert "--n must be at least 1" in result.stderr
