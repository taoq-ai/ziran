"""Analyze OWASP LLM Top 10 coverage in ZIRAN's attack library.

Usage:
    uv run python benchmarks/owasp_coverage.py
    uv run python benchmarks/owasp_coverage.py --json results/owasp_coverage.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import (
    OWASP_LLM_DESCRIPTIONS,
    OwaspLlmCategory,
)

# Issues tracking uncovered OWASP categories
_PLANNED_ISSUES: dict[str, str] = {
    "LLM05": "#42",
    "LLM10": "#43",
}

# Coverage thresholds
_COMPREHENSIVE = 40
_STRONG = 10


def collect_owasp_coverage() -> dict:
    """Analyze OWASP LLM Top 10 coverage."""
    library = AttackLibrary()
    vectors = library.vectors

    per_category: dict[str, dict] = {}
    covered: list[str] = []
    not_covered: list[str] = []

    for owasp_cat in OwaspLlmCategory:
        cat_key = owasp_cat.value
        matching = library.get_attacks_by_owasp(owasp_cat)
        count = len(matching)

        # Determine status
        if count >= _COMPREHENSIVE:
            status = "comprehensive"
        elif count >= _STRONG:
            status = "strong"
        elif count > 0:
            status = "moderate"
        else:
            status = "planned"

        # Collect attack categories that contribute to this OWASP category
        attack_cats: Counter[str] = Counter()
        for v in matching:
            attack_cats[v.category.value] += 1

        entry: dict = {
            "name": OWASP_LLM_DESCRIPTIONS.get(owasp_cat, cat_key),
            "vectors": count,
            "status": status,
            "attack_categories": dict(sorted(attack_cats.items())),
        }
        if count == 0 and cat_key in _PLANNED_ISSUES:
            entry["issue"] = _PLANNED_ISSUES[cat_key]

        per_category[cat_key] = entry

        if count > 0:
            covered.append(cat_key)
        else:
            not_covered.append(cat_key)

    total_owasp = len(OwaspLlmCategory)
    return {
        "total_vectors": len(vectors),
        "owasp_categories_total": total_owasp,
        "covered": sorted(covered),
        "not_covered": sorted(not_covered),
        "coverage_pct": round(len(covered) / total_owasp * 100, 1),
        "per_category": per_category,
    }


def print_summary(data: dict) -> None:
    """Print human-readable OWASP coverage summary."""
    print("OWASP LLM Top 10 Coverage")
    print(f"{'=' * 40}")
    print(
        f"Coverage: {len(data['covered'])}/{data['owasp_categories_total']} ({data['coverage_pct']}%)"
    )
    print()

    print(f"{'Category':<8} {'Name':<35} {'Vectors':>7}  Status")
    print(f"{'-' * 8} {'-' * 35} {'-' * 7}  {'-' * 15}")
    for cat_key, info in data["per_category"].items():
        issue = f" ({info['issue']})" if "issue" in info else ""
        print(f"{cat_key:<8} {info['name']:<35} {info['vectors']:>7}  {info['status']}{issue}")

    if data["not_covered"]:
        print(f"\nNot covered: {', '.join(data['not_covered'])}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP LLM Top 10 coverage")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    args = parser.parse_args()

    data = collect_owasp_coverage()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
