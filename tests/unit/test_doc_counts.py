"""Hand-written live counts in the docs match the attack library (spec 115)."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AtlasTechnique

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
README = "README.md"
ROADMAP = "docs/community/roadmap.md"
LIBRARY = "docs/reference/attack-library.md"
ATLAS = "docs/reference/benchmarks/atlas-mapping.md"


def _lines(doc: str) -> list[str]:
    return (ROOT / doc).read_text(encoding="utf-8").splitlines()


def _find(doc: str, pattern: str, joined: bool = False) -> list[tuple[int, tuple[str, ...]]]:
    """Return (line number, groups) for each match of an anchored phrase."""
    rx = re.compile(pattern)
    lines = _lines(doc)
    if joined:
        # a phrase wrapped over two lines: match each line joined to the next
        lines = [f"{a} {b.strip()}" for a, b in zip(lines, [*lines[1:], ""], strict=True)]
    return [(i, m.groups()) for i, line in enumerate(lines, 1) if (m := rx.search(line))]


def test_doc_counts_match_library() -> None:
    lib = AttackLibrary()
    vectors = lib.vectors
    live = Counter(t for v in vectors for t in v.atlas_mapping)
    files = len(list((ROOT / "ziran/application/attacks/vectors").glob("*.yaml")))
    n, cats = len(vectors), len(lib.categories)
    covered, enum = len(live), len(AtlasTechnique)

    # (doc, anchored phrase, expected tuple of numbers)
    expected = [
        (README, r"Attack coverage: (\d+) vectors", (n,), False),
        (README, r"(\d+)/(\d+) MITRE ATLAS", (covered, enum), True),
        (
            LIBRARY,
            r"\*\*(\d+) attack vectors\*\* across \*\*(\d+) YAML files\*\* and \*\*(\d+) categories",
            (n, files, cats),
            False,
        ),
        (ATLAS, r"the enum holds (\d+) techniques", (enum,), False),
        (ATLAS, r"for a (\d+)-vector library", (n,), False),
    ]
    problems = []
    for doc, pattern, want, joined in expected:
        hits = _find(doc, pattern, joined)
        if not hits:
            problems.append(f"{doc}: phrase /{pattern}/ not found")
        for line, groups in hits:
            if tuple(map(int, groups)) != want:
                problems.append(f"{doc}:{line}: says {groups}, library has {want}")

    # per-technique rows of the agent-technique table, under its own heading
    start = _find(ATLAS, r"^## Agent techniques")[0][0]
    rows = _find(ATLAS, r"^\| `(AML\.T\d+(?:\.\d+)?)` [^|]+\| (\d+) \|")
    agent = [r for r in rows if r[0] > start]
    assert len(agent) == 11, "agent-technique table rows not found"
    for line, (tech, count) in agent:
        if int(count) != live[tech]:
            problems.append(f"{ATLAS}:{line}: {tech} says {count}, library has {live[tech]}")

    # historical roadmap milestones carry no live count
    stale = r"\d+\+? (?:[\w-]+ )*?vectors|\d+/\d+ techniques"
    for line, _ in _find(ROADMAP, stale):
        problems.append(f"{ROADMAP}:{line}: historical entry carries a count")

    assert not problems, "\n".join(problems)
