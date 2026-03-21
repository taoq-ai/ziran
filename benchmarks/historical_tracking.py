"""Historical tracking and trend analysis for benchmark metrics.

Stores timestamped benchmark snapshots and generates trend data
for tracking coverage evolution over time.

Usage:
    uv run python benchmarks/historical_tracking.py --snapshot
    uv run python benchmarks/historical_tracking.py --trends
    uv run python benchmarks/historical_tracking.py --json results/trends.json
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

HISTORY_DIR = Path(__file__).parent / "results" / "history"


def take_snapshot() -> dict:
    """Capture a timestamped benchmark snapshot."""
    inventory = collect_inventory()
    owasp = collect_owasp_coverage()
    benchmarks = collect_benchmark_comparison()

    snapshot = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "metrics": {
            "total_vectors": inventory["total_vectors"],
            "categories": len(inventory["categories"]),
            "owasp_coverage_pct": owasp["coverage_pct"],
            "owasp_covered": len(owasp["covered"]),
            "multi_turn_vectors": inventory["multi_turn_vectors"],
            "encoding_types": inventory["encoding_types"],
            "harm_category_count": inventory["harm_category_count"],
            "tactics_count": len(inventory["tactics"]),
            "benchmarks_analyzed": benchmarks["total_benchmarks"],
        },
    }

    return snapshot


def save_snapshot(snapshot: dict) -> Path:
    """Save a snapshot to the history directory."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.fromisoformat(snapshot["timestamp"])
    filename = f"snapshot_{ts.strftime('%Y%m%d_%H%M%S')}.json"
    path = HISTORY_DIR / filename
    path.write_text(json.dumps(snapshot, indent=2) + "\n")
    return path


def load_history() -> list[dict]:
    """Load all historical snapshots sorted by timestamp."""
    if not HISTORY_DIR.exists():
        return []

    snapshots: list[dict] = []
    for path in sorted(HISTORY_DIR.glob("snapshot_*.json")):
        with open(path) as f:
            snapshots.append(json.load(f))

    return snapshots


def compute_trends(history: list[dict]) -> dict:
    """Compute trends from historical snapshots.

    Returns trend data for each tracked metric including:
    - Current value
    - Previous value
    - Delta (change)
    - Direction (up/down/stable)
    - History (all values over time)
    """
    if not history:
        return {"trend_count": 0, "trends": {}, "history_points": 0}

    current = history[-1]["metrics"]
    previous = history[-2]["metrics"] if len(history) >= 2 else current

    trends: dict[str, dict] = {}
    for metric_name in current:
        current_val = current[metric_name]
        previous_val = previous.get(metric_name, current_val)
        delta = current_val - previous_val

        if delta > 0:
            direction = "up"
        elif delta < 0:
            direction = "down"
        else:
            direction = "stable"

        trends[metric_name] = {
            "current": current_val,
            "previous": previous_val,
            "delta": delta,
            "direction": direction,
            "history": [
                {
                    "timestamp": s["timestamp"],
                    "value": s["metrics"].get(metric_name),
                }
                for s in history
                if metric_name in s.get("metrics", {})
            ],
        }

    return {
        "trend_count": len(trends),
        "trends": trends,
        "history_points": len(history),
        "first_snapshot": history[0]["timestamp"],
        "last_snapshot": history[-1]["timestamp"],
    }


def collect_historical_tracking() -> dict:
    """Collect historical tracking data including current snapshot and trends."""
    # Take current snapshot
    snapshot = take_snapshot()

    # Load history and add current
    history = load_history()

    # Compute trends (use current snapshot if no history exists yet)
    trends = compute_trends(history) if history else compute_trends([snapshot])

    return {
        "current_snapshot": snapshot,
        "trends": trends,
        "history_count": len(history),
    }


def print_summary(data: dict) -> None:
    """Print human-readable historical tracking."""
    print("Historical Tracking & Trends")
    print("=" * 60)

    snapshot = data["current_snapshot"]
    print(f"\nCurrent Snapshot ({snapshot['timestamp'][:10]}):")
    for metric, value in snapshot["metrics"].items():
        print(f"  {metric}: {value}")

    trends = data["trends"]
    if trends["history_points"] > 1:
        print(f"\nTrends (over {trends['history_points']} snapshots):")
        for metric, trend in trends["trends"].items():
            arrow = {"up": "+", "down": "-", "stable": "="}[trend["direction"]]
            print(f"  [{arrow}] {metric}: {trend['current']} (delta: {trend['delta']:+})")
    else:
        print("\nNo historical data yet. Run --snapshot to start tracking.")

    print(f"\nHistory: {data['history_count']} snapshots stored")


def main() -> None:
    parser = argparse.ArgumentParser(description="Historical tracking and trends")
    parser.add_argument("--snapshot", action="store_true", help="Take and save a new snapshot")
    parser.add_argument("--trends", action="store_true", help="Show trend analysis")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    args = parser.parse_args()

    if args.snapshot:
        snapshot = take_snapshot()
        path = save_snapshot(snapshot)
        print(f"Snapshot saved to {path}", file=sys.stderr)
        if not args.json and not args.trends:
            print(json.dumps(snapshot, indent=2))
            return

    data = collect_historical_tracking()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
