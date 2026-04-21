"""Integration tests for ``benchmarks/atlas_coverage.py``.

Validates JSON output shape, determinism (byte-identity on repeated runs), and
exit-code semantics against the real library.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
SCRIPT = REPO_ROOT / "benchmarks" / "atlas_coverage.py"


def _run(args: list[str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.integration
def test_default_run_exits_zero_with_fully_mapped_library() -> None:
    result = _run([])
    assert result.returncode == 0, (
        f"Expected exit 0 but got {result.returncode}. stderr: {result.stderr}"
    )
    assert "MITRE ATLAS Technique Coverage" in result.stdout


@pytest.mark.integration
def test_json_output_matches_expected_schema(tmp_path: Path) -> None:
    out = tmp_path / "atlas.json"
    result = _run(["--json", str(out)])
    assert result.returncode == 0, result.stderr
    data = json.loads(out.read_text())

    # Required top-level keys (per contract spec).
    for key in (
        "snapshot_date",
        "totals",
        "per_tactic",
        "per_technique",
        "uncovered_techniques",
        "uncovered_agent_specific",
        "vectors_without_mapping",
    ):
        assert key in data, f"Missing top-level key: {key}"

    totals = data["totals"]
    for key in (
        "vectors_total",
        "vectors_with_atlas_mapping",
        "vectors_without_atlas_mapping",
        "techniques_covered",
        "techniques_total_in_enum",
        "agent_specific_covered",
        "agent_specific_total",
    ):
        assert key in totals

    # Post-retro-mapping invariants:
    assert totals["vectors_without_atlas_mapping"] == 0
    assert totals["agent_specific_covered"] == totals["agent_specific_total"] == 14
    assert totals["techniques_covered"] >= 60  # Spec SC-001


@pytest.mark.integration
def test_output_is_deterministic(tmp_path: Path) -> None:
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"
    r1 = _run(["--json", str(out_a)])
    r2 = _run(["--json", str(out_b)])
    assert r1.returncode == 0 and r2.returncode == 0
    # Downstream signing depends on byte-identity across runs.
    assert out_a.read_bytes() == out_b.read_bytes()


@pytest.mark.integration
def test_strict_mode_also_passes() -> None:
    # With ≥60 techniques covered, --strict must also succeed.
    result = _run(["--strict"])
    assert result.returncode == 0, f"stderr: {result.stderr}"
