"""Unit tests for the semantic embedding tier (spec 042, FR-001/FR-004/FR-008)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from benchmarks.detection_accuracy import DATASET_DIR, load_examples
from ziran.application.detectors.semantic import (
    REFUSAL_EXEMPLARS,
    SUCCESS_EXEMPLARS,
    SemanticConfig,
    SemanticDetector,
    cosine,
    embedding_input,
)
from ziran.domain.interfaces.embedder import BaseEmbedder

if TYPE_CHECKING:
    from collections.abc import Sequence

pytestmark = pytest.mark.unit


class TableEmbedder(BaseEmbedder):
    """Lookup-table embedder: refusal exemplars ~[1,0,0], success ~[0,1,0], rest [0,0,1]."""

    def __init__(self, table: dict[str, list[float]] | None = None) -> None:
        self.table: dict[str, list[float]] = {
            **{t: [1.0, 0.01 * i, 0.0] for i, t in enumerate(REFUSAL_EXEMPLARS)},
            **{t: [0.01 * i, 1.0, 0.0] for i, t in enumerate(SUCCESS_EXEMPLARS)},
            **(table or {}),
        }
        self.calls: list[list[str]] = []
        self.fail_next = 0
        self.short = False

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        await asyncio.sleep(0)
        if self.fail_next:
            self.fail_next -= 1
            raise RuntimeError("boom")
        vectors = [self.table.get(t, [0.0, 0.0, 1.0]) for t in texts]
        return vectors[:-1] if self.short else vectors


def _exemplar_calls(emb: TableEmbedder) -> int:
    return sum(1 for c in emb.calls if len(c) == len(REFUSAL_EXEMPLARS) + len(SUCCESS_EXEMPLARS))


# ── helpers ───────────────────────────────────────────────────────────


def test_cosine_basics() -> None:
    assert cosine([1.0, 2.0], [1.0, 2.0]) == pytest.approx(1.0)
    assert cosine([1.0, 0.0], [0.0, 1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 1.0]) == 0.0
    with pytest.raises(ValueError):
        cosine([1.0], [1.0, 2.0])


def test_embedding_input_strips_and_truncates() -> None:
    assert embedding_input("  abc  ", 2) == "ab"


def test_config_defaults_and_validation() -> None:
    cfg = SemanticConfig()
    assert cfg.enabled is False
    assert cfg.model == "ollama/nomic-embed-text"
    assert cfg.base_url is None and cfg.api_key_env is None
    assert (cfg.refusal_threshold, cfg.success_threshold, cfg.margin) == (0.75, 0.80, 0.05)
    assert (cfg.max_chars, cfg.timeout_seconds) == (2000, 10.0)
    for bad in ({"margin": 1.5}, {"max_chars": 0}, {"timeout_seconds": 0}, {"bogus": 1}):
        with pytest.raises(ValidationError):
            SemanticConfig(**bad)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        cfg.enabled = True  # type: ignore[misc]


# ── detector decisions ────────────────────────────────────────────────


async def test_refusal_success_and_ambiguous() -> None:
    emb = TableEmbedder({"nope": [0.9, 0.1, 0.0], "yes": [0.1, 0.9, 0.0], "both": [1.0, 1.0, 0.0]})
    det = SemanticDetector(emb, SemanticConfig(enabled=True))
    assert det.name == "semantic"

    refusal = await det.detect("nope")
    assert refusal.detector_name == "semantic"
    assert refusal.score == 0.0
    assert refusal.reasoning.startswith("semantic refusal: similarity ")
    assert refusal.confidence == pytest.approx(cosine([0.9, 0.1, 0.0], [1.0, 0.0, 0.0]), abs=0.01)

    success = await det.detect("yes")
    assert success.score == 1.0
    assert success.reasoning.startswith("semantic success: similarity ")

    ambiguous = await det.detect("unrelated")
    assert (ambiguous.score, ambiguous.confidence) == (0.5, 0.0)
    assert ambiguous.reasoning.startswith("semantic ambiguous: ")

    # Both similarities ~0.707 (above thresholds 0.6) but within margin -> ambiguous.
    within = await SemanticDetector(
        emb, SemanticConfig(refusal_threshold=0.6, success_threshold=0.6)
    ).detect("both")
    assert within.score == 0.5

    for r in (refusal, success, ambiguous, within):
        assert r.matched_indicators == []


async def test_detect_embeds_stripped_truncated_text() -> None:
    emb = TableEmbedder()
    await SemanticDetector(emb, SemanticConfig(max_chars=3)).detect("  abcdef ")
    assert emb.calls[-1] == ["abc"]


async def test_exemplars_embedded_once() -> None:
    emb = TableEmbedder()
    det = SemanticDetector(emb, SemanticConfig())
    for _ in range(3):
        await det.detect("x")
    assert _exemplar_calls(emb) == 1

    emb2 = TableEmbedder()
    det2 = SemanticDetector(emb2, SemanticConfig())
    await asyncio.gather(*(det2.detect("x") for _ in range(5)))
    assert _exemplar_calls(emb2) == 1


async def test_failed_exemplar_embedding_is_retried() -> None:
    emb = TableEmbedder()
    emb.fail_next = 1
    det = SemanticDetector(emb, SemanticConfig())
    with pytest.raises(RuntimeError):
        await det.detect("x")
    result = await det.detect("x")
    assert result.score == 0.5
    assert _exemplar_calls(emb) == 2


async def test_wrong_vector_count_raises() -> None:
    emb = TableEmbedder()
    emb.short = True
    with pytest.raises(ValueError):
        await SemanticDetector(emb, SemanticConfig()).detect("x")


def test_exemplars_do_not_leak_from_dataset() -> None:
    assert len(REFUSAL_EXEMPLARS) == 16 and len(SUCCESS_EXEMPLARS) == 8
    responses = [ex.response_text.lower() for ex in load_examples(DATASET_DIR)]
    for exemplar in (*REFUSAL_EXEMPLARS, *SUCCESS_EXEMPLARS):
        assert not any(exemplar.lower() in r for r in responses), exemplar
