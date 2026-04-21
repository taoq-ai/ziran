"""Analyze MITRE ATLAS technique coverage in ZIRAN's attack library.

Usage:
    uv run python benchmarks/atlas_coverage.py
    uv run python benchmarks/atlas_coverage.py --json results/atlas_coverage.json
    uv run python benchmarks/atlas_coverage.py --strict  # non-zero exit on gaps
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ziran.application.attacks.library import get_attack_library
from ziran.domain.entities.attack import (
    AGENT_SPECIFIC_TECHNIQUES,
    ATLAS_TACTIC_DESCRIPTIONS,
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_TO_TACTIC,
    AtlasTactic,
    AtlasTechnique,
)

# Snapshot date matches the ATLAS release the enum was pinned to (see attack.py docstrings).
_SNAPSHOT_DATE = "2025-10-01"

# Minimum technique-coverage floor (spec 012 SC-001: ≥ 60 distinct techniques).
_TECHNIQUES_FLOOR = 60


def collect_atlas_coverage() -> dict[str, Any]:
    """Walk the attack library and produce the ATLAS coverage summary.

    The output schema matches ``specs/012-benchmark-maturity/contracts/benchmark-reports.md``.
    Keys and nested-dict contents are sorted so that the JSON output is
    byte-identical across repeated runs (downstream signing requires this).
    """
    library = get_attack_library()
    vectors = list(library.vectors)

    # Per-technique vector counts.
    per_technique: dict[str, dict[str, Any]] = {}
    for technique in AtlasTechnique:
        matching = library.get_attacks_by_atlas(technique)
        tactics = ATLAS_TECHNIQUE_TO_TACTIC[technique]
        per_technique[technique.value] = {
            "name": ATLAS_TECHNIQUE_DESCRIPTIONS[technique],
            "tactics": sorted(t.value for t in tactics),
            "agent_specific": technique in AGENT_SPECIFIC_TECHNIQUES,
            "vector_count": len(matching),
        }

    # Per-tactic roll-up.
    per_tactic: dict[str, dict[str, Any]] = {}
    for tactic in AtlasTactic:
        techniques_in_tactic: list[AtlasTechnique] = [
            t for t, parents in ATLAS_TECHNIQUE_TO_TACTIC.items() if tactic in parents
        ]
        covered_techniques = [
            t for t in techniques_in_tactic if per_technique[t.value]["vector_count"] > 0
        ]
        vector_count = sum(per_technique[t.value]["vector_count"] for t in techniques_in_tactic)
        per_tactic[tactic.value] = {
            "tactic_name": ATLAS_TACTIC_DESCRIPTIONS[tactic],
            "techniques_covered": len(covered_techniques),
            "techniques_total": len(techniques_in_tactic),
            "vector_count": vector_count,
        }

    # Coverage totals.
    vectors_with_mapping = [v for v in vectors if v.atlas_mapping]
    offending_vector_ids: list[str] = sorted(v.id for v in vectors if not v.atlas_mapping)
    techniques_covered: list[str] = sorted(
        tech_id for tech_id, data in per_technique.items() if data["vector_count"] > 0
    )
    uncovered_techniques: list[str] = sorted(
        tech_id for tech_id, data in per_technique.items() if data["vector_count"] == 0
    )
    agent_specific_covered: list[str] = sorted(
        t.value for t in AGENT_SPECIFIC_TECHNIQUES if per_technique[t.value]["vector_count"] > 0
    )
    uncovered_agent_specific: list[str] = sorted(
        t.value for t in AGENT_SPECIFIC_TECHNIQUES if per_technique[t.value]["vector_count"] == 0
    )

    return {
        "snapshot_date": _SNAPSHOT_DATE,
        "totals": {
            "vectors_total": len(vectors),
            "vectors_with_atlas_mapping": len(vectors_with_mapping),
            "vectors_without_atlas_mapping": len(offending_vector_ids),
            "techniques_covered": len(techniques_covered),
            "techniques_total_in_enum": len(list(AtlasTechnique)),
            "agent_specific_covered": len(agent_specific_covered),
            "agent_specific_total": len(AGENT_SPECIFIC_TECHNIQUES),
        },
        "per_tactic": per_tactic,
        "per_technique": per_technique,
        "uncovered_techniques": uncovered_techniques,
        "uncovered_agent_specific": uncovered_agent_specific,
        "vectors_without_mapping": offending_vector_ids,
    }


def _validate(data: dict[str, Any], strict: bool) -> int:
    """Return the desired exit code based on the coverage data.

    - Always non-zero if any vector has empty ``atlas_mapping``.
    - Always non-zero if fewer than 14 agent-specific techniques are covered.
    - Non-zero under ``--strict`` if fewer than ``_TECHNIQUES_FLOOR`` techniques covered.
    """
    totals = data["totals"]
    if totals["vectors_without_atlas_mapping"] > 0:
        print(
            f"FAIL: {totals['vectors_without_atlas_mapping']} vectors lack an atlas_mapping. "
            f"Run with --json to see the list, or inspect `vectors_without_mapping`.",
            file=sys.stderr,
        )
        return 1
    if totals["agent_specific_covered"] < totals["agent_specific_total"]:
        missing = ", ".join(data["uncovered_agent_specific"])
        print(
            f"FAIL: {totals['agent_specific_total'] - totals['agent_specific_covered']} "
            f"agent-specific techniques not covered: {missing}",
            file=sys.stderr,
        )
        return 1
    if strict and totals["techniques_covered"] < _TECHNIQUES_FLOOR:
        print(
            f"FAIL (strict): {totals['techniques_covered']} techniques covered, "
            f"floor is {_TECHNIQUES_FLOOR}.",
            file=sys.stderr,
        )
        return 1
    return 0


def print_summary(data: dict[str, Any]) -> None:
    """Print human-readable ATLAS coverage summary."""
    totals = data["totals"]
    print("MITRE ATLAS Technique Coverage")
    print(f"{'=' * 40}")
    print(f"Snapshot: {data['snapshot_date']}")
    print(
        f"Techniques covered:     {totals['techniques_covered']}/{totals['techniques_total_in_enum']}"
    )
    print(
        f"Agent-specific covered: {totals['agent_specific_covered']}/{totals['agent_specific_total']}"
    )
    print(
        f"Vectors with mapping:   {totals['vectors_with_atlas_mapping']}/{totals['vectors_total']}"
    )
    print()

    print(f"{'Tactic':<12} {'Name':<28} {'Techniques':>12}  {'Vectors':>8}")
    print(f"{'-' * 12} {'-' * 28} {'-' * 12}  {'-' * 8}")
    for tactic_id, info in data["per_tactic"].items():
        tech_frac = f"{info['techniques_covered']}/{info['techniques_total']}"
        print(
            f"{tactic_id:<12} {info['tactic_name']:<28} {tech_frac:>12}  {info['vector_count']:>8}"
        )

    if data["uncovered_agent_specific"]:
        print(
            f"\nUncovered agent-specific techniques: {', '.join(data['uncovered_agent_specific'])}"
        )
    if data["vectors_without_mapping"]:
        sample = ", ".join(data["vectors_without_mapping"][:5])
        suffix = ", …" if len(data["vectors_without_mapping"]) > 5 else ""
        print(
            f"\nVectors without atlas_mapping "
            f"({len(data['vectors_without_mapping'])}): {sample}{suffix}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="MITRE ATLAS technique coverage")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=f"Exit non-zero if fewer than {_TECHNIQUES_FLOOR} techniques are covered",
    )
    args = parser.parse_args()

    data = collect_atlas_coverage()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        # sort_keys=True + newline suffix → byte-identical output across runs.
        args.json.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)

    sys.exit(_validate(data, strict=args.strict))


if __name__ == "__main__":
    main()
