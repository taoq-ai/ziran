"""Offline embedder that replays a recorded embedding cassette (spec 042).

Vectors are keyed by the SHA-256 of the exact embedded text, so the committed
cassette never contains response text. Mirrors the spec-022 cassette pattern.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from ziran.domain.interfaces.embedder import BaseEmbedder

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class EmbeddingCassette(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    model: str
    recorded_at: str
    vectors: dict[str, list[float]]


def text_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class MissingEmbeddingError(LookupError):
    """A text has no recorded vector (message names the key prefix, never the text)."""


class ReplayEmbedder(BaseEmbedder):
    def __init__(self, cassette: EmbeddingCassette) -> None:
        self._vectors = cassette.vectors

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            key = text_key(text)
            if key not in self._vectors:
                raise MissingEmbeddingError(f"no recorded vector for text key {key[:12]}")
            out.append(self._vectors[key])
        return out

    def missing(self, texts: Iterable[str]) -> list[str]:
        return [k for k in map(text_key, texts) if k not in self._vectors]
