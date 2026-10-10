"""Sample CrewAI units from a saved ``ziran audit --format json`` output for a hand check.

    python scripts/sample_crewai_units.py audit.json --seed N [--n 50]

The frame is every unit in the document's ``crewai`` list without errors, sorted by
``(file, agent)`` so the sample does not depend on discovery order. ``random.Random(seed)``
draws ``min(n, frame)`` units. The script only samples and prints; people judge the output.
Exit 2 when the file cannot be read or has no ``crewai`` list.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, NoReturn


def _fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def _load_units(path: Path) -> list[dict[str, Any]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {path} ({type(exc).__name__})")
    units = doc.get("crewai") if isinstance(doc, dict) else None
    if not isinstance(units, list):
        _fail(f"{path} has no crewai list; run ziran audit --format json on a CrewAI project")
    return units


def _block(index: int, unit: dict[str, Any]) -> str:
    lines = [
        f"unit {unit['agent']} #{index}",
        f"  file: {unit['file']}:{unit['line']}",
        f"  agent_tools: {', '.join(unit['agent_tools']) or '-'}",
    ]
    lines += [f"  task {t['name']}: {', '.join(t['tools']) or '-'}" for t in unit["tasks"]]
    lines.append(f"  tools: {', '.join(unit['tools']) or '-'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("audit_json", type=Path)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--n", type=int, default=50)
    args = parser.parse_args(argv)
    if args.n < 1:
        parser.error("--n must be at least 1")

    units = _load_units(args.audit_json)
    frame = sorted((u for u in units if not u["errors"]), key=lambda u: (u["file"], u["agent"]))
    sample = random.Random(args.seed).sample(frame, min(args.n, len(frame)))
    print(
        f"seed={args.seed} n={args.n} frame={len(frame)} "
        f"left_out_with_errors={len(units) - len(frame)}"
    )
    for index, unit in enumerate(sample, 1):
        print()
        print(_block(index, unit))


if __name__ == "__main__":
    main()
