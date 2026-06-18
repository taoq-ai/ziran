"""Corpus-safety unit tests (spec 023, T007, FR-004).

The shot corpus must be synthetic/non-operational — these tests guard that
boundary. (The vector↔corpus key cross-check lives in test_many_shot_vectors.py.)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

_CORPUS = Path("ziran/application/attacks/many_shot_corpus.yaml")

# Markers that would suggest real operational payloads slipped into the corpus.
_BANNED = [
    "import os",
    "subprocess",
    "rm -rf",
    "curl http",
    "wget http",
    "/etc/passwd",
    "DROP TABLE",
    "powershell",
    "base64 -d",
    "chmod +x",
    "nc -e",
    "metasploit",
]


def _corpus() -> dict[str, list[dict[str, str]]]:
    return (yaml.safe_load(_CORPUS.read_text(encoding="utf-8")) or {}).get("corpus", {})


def test_every_key_has_nonempty_ordered_shots() -> None:
    corpus = _corpus()
    assert corpus, "corpus is empty"
    for key, shots in corpus.items():
        assert isinstance(shots, list) and shots, f"corpus key {key} has no shots"
        for shot in shots:
            assert shot.get("q") and shot.get("a"), f"corpus key {key} has an incomplete shot"


def test_corpus_has_no_operational_markers() -> None:
    text = _CORPUS.read_text(encoding="utf-8").lower()
    hits = [m for m in _BANNED if m.lower() in text]
    assert not hits, f"corpus appears to contain operational content: {hits}"


def test_shots_declare_synthetic_intent() -> None:
    # Each answer should signal it is synthetic/illustrative (defensive marker).
    for shots in _corpus().values():
        for shot in shots:
            assert any(w in shot["a"].lower() for w in ("synthetic", "illustrative", "placeholder"))
