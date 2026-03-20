"""Benchmark regression detection.

Compares current benchmark metrics against a stored baseline and fails
if coverage has dropped below acceptable thresholds.

Usage:
    uv run python benchmarks/regression_check.py
    uv run python benchmarks/regression_check.py --format markdown
    uv run python benchmarks/regression_check.py --update-baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.benchmark_comparison import collect_benchmark_comparison
from benchmarks.inventory import collect_inventory
from benchmarks.owasp_coverage import collect_owasp_coverage

BASELINE_PATH = Path(__file__).parent / "results" / "baseline.json"
RESULTS_DIR = Path(__file__).parent / "results"


def _collect_current_metrics() -> dict:
    """Collect current benchmark metrics."""
    inventory = collect_inventory()
    owasp = collect_owasp_coverage()
    benchmarks = collect_benchmark_comparison()

    return {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "total_vectors": inventory["total_vectors"],
        "categories": len(inventory["categories"]),
        "owasp_coverage_pct": owasp["coverage_pct"],
        "owasp_covered": len(owasp["covered"]),
        "multi_turn_vectors": inventory["multi_turn_vectors"],
        "harm_category_count": inventory["harm_category_count"],
        "tactics_count": len(inventory["tactics"]),
        "benchmark_count": benchmarks["total_benchmarks"],
        "benchmark_details": {
            b["name"]: {
                "status": b["gap_status"],
                "metrics": [
                    {
                        "dimension": m["dimension"],
                        "implemented": m["implemented"],
                        "target": m["target"],
                        "pct": m["pct"],
                    }
                    for m in b["metrics"]
                ],
            }
            for b in benchmarks["benchmarks"]
        },
    }


def _load_baseline() -> dict | None:
    """Load stored baseline. Returns None if no baseline exists."""
    if not BASELINE_PATH.exists():
        return None
    return json.loads(BASELINE_PATH.read_text())


def _check_regressions(current: dict, baseline: dict) -> list[str]:
    """Compare current metrics against baseline. Return list of regressions."""
    regressions: list[str] = []

    # Core metrics that must not decrease
    checks = [
        ("total_vectors", "Total attack vectors"),
        ("categories", "Attack categories"),
        ("owasp_covered", "OWASP categories covered"),
        ("multi_turn_vectors", "Multi-turn vectors"),
        ("harm_category_count", "Harm categories"),
        ("tactics_count", "Tactics count"),
    ]

    for key, label in checks:
        curr_val = current.get(key, 0)
        base_val = baseline.get(key, 0)
        if curr_val < base_val:
            regressions.append(
                f"{label} decreased: {base_val} -> {curr_val} (delta: {curr_val - base_val})"
            )

    # OWASP coverage percentage
    curr_owasp = current.get("owasp_coverage_pct", 0)
    base_owasp = baseline.get("owasp_coverage_pct", 0)
    if curr_owasp < base_owasp:
        regressions.append(f"OWASP coverage dropped: {base_owasp}% -> {curr_owasp}%")

    return regressions


def _format_summary(current: dict, baseline: dict | None) -> str:
    """Format human-readable summary."""
    lines = [
        "Benchmark Coverage Summary",
        "=" * 40,
        f"Total vectors:     {current['total_vectors']}",
        f"Categories:        {current['categories']}",
        f"OWASP coverage:    {current['owasp_coverage_pct']}%",
        f"Multi-turn:        {current['multi_turn_vectors']}",
        f"Harm categories:   {current['harm_category_count']}",
        f"Tactics:           {current['tactics_count']}",
        "",
    ]

    if baseline:
        regressions = _check_regressions(current, baseline)
        if regressions:
            lines.append("REGRESSIONS DETECTED:")
            for r in regressions:
                lines.append(f"  - {r}")
        else:
            deltas = []
            for key, label in [
                ("total_vectors", "Vectors"),
                ("owasp_covered", "OWASP categories"),
                ("multi_turn_vectors", "Multi-turn"),
            ]:
                delta = current.get(key, 0) - baseline.get(key, 0)
                if delta > 0:
                    deltas.append(f"{label}: +{delta}")
            if deltas:
                lines.append("Improvements: " + ", ".join(deltas))
            else:
                lines.append("No changes from baseline.")
    else:
        lines.append("No baseline found. Run with --update-baseline to create one.")

    return "\n".join(lines)


def _format_markdown(current: dict, baseline: dict | None) -> str:
    """Format markdown summary for PR comments."""
    lines = [
        "## Benchmark Coverage Report",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Attack vectors | **{current['total_vectors']}** |",
        f"| Categories | **{current['categories']}** |",
        f"| OWASP coverage | **{current['owasp_coverage_pct']}%** |",
        f"| Multi-turn vectors | **{current['multi_turn_vectors']}** |",
        f"| Harm categories | **{current['harm_category_count']}** |",
        f"| Tactics | **{current['tactics_count']}** |",
        "",
    ]

    if baseline:
        regressions = _check_regressions(current, baseline)
        if regressions:
            lines.append(":x: **Regressions detected:**")
            for r in regressions:
                lines.append(f"- {r}")
        else:
            lines.append(":white_check_mark: No regressions detected.")
            deltas = []
            for key, label in [
                ("total_vectors", "Vectors"),
                ("multi_turn_vectors", "Multi-turn"),
                ("harm_category_count", "Harm categories"),
            ]:
                delta = current.get(key, 0) - baseline.get(key, 0)
                if delta > 0:
                    deltas.append(f"**{label}**: +{delta}")
            if deltas:
                lines.append("")
                lines.append("**Changes:** " + " | ".join(deltas))
    else:
        lines.append("_No baseline available for comparison._")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark regression check")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update the stored baseline with current metrics",
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format",
    )
    args = parser.parse_args()

    current = _collect_current_metrics()
    baseline = _load_baseline()

    if args.update_baseline:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps(current, indent=2) + "\n")
        print(f"Baseline updated: {BASELINE_PATH}", file=sys.stderr)
        return

    if args.format == "markdown":
        print(_format_markdown(current, baseline))
    else:
        print(_format_summary(current, baseline))

    # Fail if regressions detected
    if baseline:
        regressions = _check_regressions(current, baseline)
        if regressions:
            print(f"\nFAILED: {len(regressions)} regression(s) detected", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
