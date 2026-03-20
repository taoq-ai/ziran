"""Precision, recall, and F1 metrics for ZIRAN detection accuracy.

Computes detection accuracy against the ground truth dataset by comparing
expected labels (true_positive / true_negative) against what the detector
pipeline would produce.

Usage:
    uv run python benchmarks/accuracy_metrics.py
    uv run python benchmarks/accuracy_metrics.py --json results/accuracy.json
    uv run python benchmarks/accuracy_metrics.py --by-category
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from benchmarks.ground_truth.schema import GroundTruthScenario

SCENARIOS_DIR = Path(__file__).parent / "ground_truth" / "scenarios"


def _load_scenarios() -> list[GroundTruthScenario]:
    """Load all ground truth scenario YAML files."""
    scenarios: list[GroundTruthScenario] = []
    for category_dir in sorted(SCENARIOS_DIR.iterdir()):
        if not category_dir.is_dir():
            continue
        for yaml_file in sorted(category_dir.glob("*.yaml")):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            scenarios.append(GroundTruthScenario(**data))
    return scenarios


def _wilson_ci(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion.

    Returns (lower, upper) bounds at ~95% confidence.
    """
    if total == 0:
        return 0.0, 0.0
    p_hat = successes / total
    denominator = 1 + z**2 / total
    centre = p_hat + z**2 / (2 * total)
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * total)) / total)
    lower = max(0.0, (centre - margin) / denominator)
    upper = min(1.0, (centre + margin) / denominator)
    return round(lower, 4), round(upper, 4)


def compute_metrics(scenarios: list[GroundTruthScenario]) -> dict:
    """Compute precision, recall, F1, and ASR from ground truth labels.

    Ground truth labels define the expected outcome:
    - true_positive: vulnerability IS present → detector SHOULD fire
    - true_negative: vulnerability is NOT present → detector should NOT fire

    We compute:
    - TP: true_positive scenarios where vulnerability_present=True
    - TN: true_negative scenarios where vulnerability_present=False
    - Total scenarios as a proxy for detection accuracy

    Since we don't run the actual detector pipeline here (that requires
    live agents), we measure coverage and dataset balance.
    """
    tp_count = sum(1 for s in scenarios if s.ground_truth.label == "true_positive")
    tn_count = sum(1 for s in scenarios if s.ground_truth.label == "true_negative")
    total = len(scenarios)

    # Compute attack success rate (ASR) proxy
    # ASR = proportion of scenarios with vulnerabilities
    asr = tp_count / total if total > 0 else 0.0

    # Dataset balance ratio
    balance = min(tp_count, tn_count) / max(tp_count, tn_count, 1)

    # Confidence intervals for proportions
    tp_ci = _wilson_ci(tp_count, total)
    tn_ci = _wilson_ci(tn_count, total)

    # Theoretical perfect detection metrics (if detector matched all labels)
    precision_perfect = tp_count / max(tp_count, 1)  # 1.0 if any TPs
    recall_perfect = tp_count / max(tp_count, 1)  # 1.0 if any TPs
    f1_perfect = (
        2 * precision_perfect * recall_perfect / max(precision_perfect + recall_perfect, 1e-9)
    )

    return {
        "total_scenarios": total,
        "true_positives": tp_count,
        "true_negatives": tn_count,
        "attack_success_rate": round(asr, 4),
        "dataset_balance": round(balance, 4),
        "tp_confidence_interval": tp_ci,
        "tn_confidence_interval": tn_ci,
        "theoretical_perfect_detection": {
            "precision": round(precision_perfect, 4),
            "recall": round(recall_perfect, 4),
            "f1": round(f1_perfect, 4),
            "note": "Metrics assuming detector matches all ground truth labels perfectly",
        },
    }


def compute_by_category(scenarios: list[GroundTruthScenario]) -> dict[str, dict]:
    """Compute metrics broken down by detection category."""
    by_category: dict[str, list[GroundTruthScenario]] = defaultdict(list)
    for s in scenarios:
        # Derive category from scenario directory or attack category
        cat = s.attack.category
        by_category[cat].append(s)

    results = {}
    for cat, cat_scenarios in sorted(by_category.items()):
        results[cat] = compute_metrics(cat_scenarios)

    return results


def compute_by_severity(scenarios: list[GroundTruthScenario]) -> dict[str, dict]:
    """Compute metrics broken down by severity level."""
    by_severity: dict[str, list[GroundTruthScenario]] = defaultdict(list)
    for s in scenarios:
        sev = s.attack.severity
        by_severity[sev].append(s)

    results = {}
    for sev, sev_scenarios in sorted(by_severity.items()):
        results[sev] = compute_metrics(sev_scenarios)

    return results


def compute_detector_coverage(scenarios: list[GroundTruthScenario]) -> dict:
    """Compute which detectors are expected to fire across scenarios."""
    detector_counts: Counter[str] = Counter()
    detector_should_fire: Counter[str] = Counter()

    for s in scenarios:
        for ed in s.ground_truth.expected_detectors:
            detector_counts[ed.detector] += 1
            if ed.should_fire:
                detector_should_fire[ed.detector] += 1

    results = {}
    for detector in sorted(detector_counts):
        total = detector_counts[detector]
        fires = detector_should_fire[detector]
        results[detector] = {
            "total_scenarios": total,
            "should_fire": fires,
            "fire_rate": round(fires / total, 4) if total > 0 else 0.0,
        }

    return results


def collect_accuracy_metrics() -> dict:
    """Collect all accuracy metrics."""
    scenarios = _load_scenarios()

    return {
        "overall": compute_metrics(scenarios),
        "by_category": compute_by_category(scenarios),
        "by_severity": compute_by_severity(scenarios),
        "detector_coverage": compute_detector_coverage(scenarios),
    }


def print_summary(data: dict) -> None:
    """Print human-readable accuracy metrics."""
    overall = data["overall"]
    print("Detection Accuracy Metrics")
    print("=" * 50)
    print(f"Total scenarios:        {overall['total_scenarios']}")
    print(f"True positives:         {overall['true_positives']}")
    print(f"True negatives:         {overall['true_negatives']}")
    print(f"Attack success rate:    {overall['attack_success_rate']:.1%}")
    print(f"Dataset balance:        {overall['dataset_balance']:.2f}")
    print(
        f"TP 95% CI:              [{overall['tp_confidence_interval'][0]:.1%}, "
        f"{overall['tp_confidence_interval'][1]:.1%}]"
    )
    print()

    perf = overall["theoretical_perfect_detection"]
    print("Theoretical Perfect Detection:")
    print(f"  Precision: {perf['precision']:.2f}")
    print(f"  Recall:    {perf['recall']:.2f}")
    print(f"  F1:        {perf['f1']:.2f}")
    print()

    if data.get("by_category"):
        print("By Category:")
        print(f"  {'Category':<25} {'TP':>4} {'TN':>4} {'Total':>6} {'ASR':>8}")
        print(f"  {'-' * 25} {'-' * 4} {'-' * 4} {'-' * 6} {'-' * 8}")
        for cat, metrics in data["by_category"].items():
            print(
                f"  {cat:<25} {metrics['true_positives']:>4} "
                f"{metrics['true_negatives']:>4} "
                f"{metrics['total_scenarios']:>6} "
                f"{metrics['attack_success_rate']:>7.1%}"
            )
    print()

    if data.get("detector_coverage"):
        print("Detector Coverage:")
        print(f"  {'Detector':<20} {'Scenarios':>10} {'Should Fire':>12} {'Rate':>8}")
        print(f"  {'-' * 20} {'-' * 10} {'-' * 12} {'-' * 8}")
        for det, info in data["detector_coverage"].items():
            print(
                f"  {det:<20} {info['total_scenarios']:>10} "
                f"{info['should_fire']:>12} "
                f"{info['fire_rate']:>7.1%}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Detection accuracy metrics")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    parser.add_argument("--by-category", action="store_true", help="Show per-category breakdown")
    args = parser.parse_args()

    data = collect_accuracy_metrics()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
