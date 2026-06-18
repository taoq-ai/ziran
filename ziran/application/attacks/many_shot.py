"""Many-shot jailbreak shot rendering (spec 023).

Builds the long-context preamble for a many-shot vector by stacking N synthetic
shots from a harm-keyed corpus before the vector's final request. Deterministic
(same key + count → identical text) and dependency-free (token count is a char
heuristic, not ``tiktoken``).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

#: Supported shot-count bounds (clarification Q3 / FR-003).
MIN_SHOTS = 1
MAX_SHOTS = 500

#: ~chars per token — coarse estimate for the context-capacity check (no tiktoken).
_CHARS_PER_TOKEN = 4

_CORPUS_PATH = Path(__file__).parent / "many_shot_corpus.yaml"


@lru_cache(maxsize=1)
def _load_corpus(path: str) -> dict[str, list[dict[str, str]]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    corpus: dict[str, list[dict[str, str]]] = data.get("corpus", {})
    return corpus


def clamp_shots(n: int) -> tuple[int, bool]:
    """Clamp *n* to [MIN_SHOTS, MAX_SHOTS]; return (value, was_clamped)."""
    clamped = min(max(n, MIN_SHOTS), MAX_SHOTS)
    return clamped, clamped != n


def estimate_tokens(text: str) -> int:
    """Coarse token estimate (~4 chars/token)."""
    return len(text) // _CHARS_PER_TOKEN


class ShotRenderer:
    """Renders N synthetic shots from the corpus for a harm-category key."""

    def __init__(self, corpus_path: Path | None = None) -> None:
        self._path = str(corpus_path or _CORPUS_PATH)

    def available_keys(self) -> set[str]:
        return set(_load_corpus(self._path))

    def render(self, corpus_key: str, n: int) -> str:
        """Assemble *n* shots for *corpus_key*, cycling the ordered list deterministically.

        The count is clamped to [MIN_SHOTS, MAX_SHOTS] first. Raises ``KeyError``
        for an unknown corpus key.
        """
        corpus = _load_corpus(self._path)
        if corpus_key not in corpus:
            raise KeyError(
                f"unknown many-shot corpus key '{corpus_key}'; available: {sorted(corpus)}"
            )
        shots = corpus[corpus_key]
        if not shots:
            raise ValueError(f"many-shot corpus key '{corpus_key}' has no shots")

        count, _ = clamp_shots(n)
        blocks = [
            f"Q: {shots[i % len(shots)]['q']}\nA: {shots[i % len(shots)]['a']}"
            for i in range(count)
        ]
        return "\n\n".join(blocks)
