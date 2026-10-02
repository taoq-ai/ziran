"""Replayed embedding cassette for the semantic benchmark (spec 042, FR-010)."""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from benchmarks.replay_embedder import (
    EmbeddingCassette,
    MissingEmbeddingError,
    ReplayEmbedder,
    text_key,
)

pytestmark = pytest.mark.unit


def _cassette(**vectors: list[float]) -> EmbeddingCassette:
    return EmbeddingCassette(
        version=1,
        model="m",
        recorded_at="2026-10-02T00:00:00+00:00",
        vectors={text_key(t): v for t, v in vectors.items()},
    )


def test_text_key_is_sha256() -> None:
    assert text_key("hé") == hashlib.sha256("hé".encode()).hexdigest()


async def test_embed_returns_vectors_in_order() -> None:
    replay = ReplayEmbedder(_cassette(a=[1.0], b=[2.0]))
    assert await replay.embed(["b", "a"]) == [[2.0], [1.0]]


async def test_missing_text_raises_without_leaking() -> None:
    replay = ReplayEmbedder(_cassette(a=[1.0]))
    with pytest.raises(MissingEmbeddingError) as exc:
        await replay.embed(["top secret response"])
    assert "top secret response" not in str(exc.value)
    assert replay.missing(["a", "zz"]) == [text_key("zz")]


def test_cassette_validation() -> None:
    base = {"model": "m", "recorded_at": "t", "vectors": {}}
    with pytest.raises(ValidationError):
        EmbeddingCassette(version=2, **base)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        EmbeddingCassette(version=1, extra=1, **base)  # type: ignore[call-arg]
