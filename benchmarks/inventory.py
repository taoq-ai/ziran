"""Introspect the ZIRAN AttackLibrary and produce a vector inventory summary.

Usage:
    uv run python benchmarks/inventory.py                # print to stdout
    uv run python benchmarks/inventory.py --json out.json # write JSON file
    uv run python benchmarks/inventory.py --pretty        # pretty-print JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from ziran.application.attacks.encoding import EncodingType
from ziran.application.attacks.library import get_attack_library
from ziran.domain.entities.attack import get_business_impacts

try:
    from ziran.domain.entities.attack import HarmCategory
except ImportError:
    HarmCategory = None  # type: ignore[assignment,misc]


def collect_inventory() -> dict:
    """Return a dict summarising every vector in the built-in library."""
    library = get_attack_library()
    vectors = library.vectors

    categories: Counter[str] = Counter()
    owasp: Counter[str] = Counter()
    tactics: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    harm_cats: Counter[str] = Counter()
    multi_turn = 0

    for v in vectors:
        categories[v.category.value] += 1
        severities[v.severity] += 1
        tactic = v.tactic or "single"
        tactics[tactic] += 1
        if tactic != "single":
            multi_turn += 1
        for o in v.owasp_mapping:
            owasp[o.value] += 1
        for t in v.tags:
            tags[t] += 1
        harm_cat = getattr(v, "harm_category", None)
        if harm_cat is not None:
            harm_cats[harm_cat.value] += 1

    # Business impact coverage per category
    bi_coverage: dict[str, list[str]] = {}
    for v in vectors:
        cat_val = v.category.value
        if cat_val not in bi_coverage:
            impacts = get_business_impacts(v.category, v.severity)
            bi_coverage[cat_val] = [i.value for i in impacts]

    return {
        "total_vectors": len(vectors),
        "categories": dict(sorted(categories.items())),
        "owasp_distribution": dict(sorted(owasp.items())),
        "tactics": dict(sorted(tactics.items())),
        "severities": dict(sorted(severities.items())),
        "encoding_types": len(EncodingType),
        "unique_tags": len(tags),
        "multi_turn_vectors": multi_turn,
        "harm_categories": dict(sorted(harm_cats.items())) if harm_cats else {},
        "harm_category_count": len(HarmCategory) if HarmCategory is not None else 0,
        "business_impact_coverage": dict(sorted(bi_coverage.items())),
    }


def print_summary(data: dict) -> None:
    """Print a human-readable summary to stdout."""
    print("ZIRAN Attack Vector Inventory")
    print(f"{'=' * 40}")
    print(f"Total vectors: {data['total_vectors']}")
    print(f"Attack categories: {len(data['categories'])}")
    print(f"OWASP categories covered: {len(data['owasp_distribution'])}/10")
    print(f"Multi-turn tactics: {len(data['tactics']) - (1 if 'single' in data['tactics'] else 0)}")
    print(f"Encoding types: {data['encoding_types']}")
    print(f"Multi-turn vectors: {data['multi_turn_vectors']}")
    print(f"Harm categories: {data['harm_category_count']}")
    print()

    print("Vectors per category:")
    for cat, count in data["categories"].items():
        print(f"  {cat}: {count}")
    print()

    print("OWASP distribution:")
    for owasp, count in data["owasp_distribution"].items():
        print(f"  {owasp}: {count}")
    print()

    print("Tactics:")
    for tactic, count in data["tactics"].items():
        print(f"  {tactic}: {count}")
    print()

    print("Severities:")
    for sev, count in data["severities"].items():
        print(f"  {sev}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ZIRAN vector inventory")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args()

    data = collect_inventory()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        indent = 2 if args.pretty else None
        args.json.write_text(json.dumps(data, indent=indent) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
