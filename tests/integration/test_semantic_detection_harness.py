"""Integration: the semantic-detection comparison harness, offline (spec 042, US4/US5)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from benchmarks.detection_accuracy import DATASET_DIR, load_examples, run_benchmark
from benchmarks.replay_embedder import EmbeddingCassette, text_key
from benchmarks.semantic_detection import main, needed_texts
from ziran.application.detectors.semantic import SemanticConfig

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

_PATCH = "ziran.infrastructure.llm.litellm_client._import_litellm"


def _vector(text: str) -> list[float]:
    """Deterministic fake vector derived from the text hash."""
    digest = bytes.fromhex(text_key(text))
    return [b / 255 for b in digest[:8]]


def _write_cassette(path: Path, drop: int = 0) -> None:
    texts = needed_texts(SemanticConfig())[drop:]
    cassette = EmbeddingCassette(
        version=1,
        model="fake/model",
        recorded_at="2026-10-02T00:00:00+00:00",
        vectors={text_key(t): _vector(t) for t in texts},
    )
    path.write_text(cassette.model_dump_json(), encoding="utf-8")


def test_default_benchmark_unchanged() -> None:
    result = run_benchmark(DATASET_DIR)
    assert set(result.detectors) == {"refusal", "indicator", "side_effect", "llm_judge"}
    cm = result.detectors["refusal"].confusion
    assert (cm.tp, cm.fp, cm.fn, cm.tn) == (52, 12, 0, 52)


def test_compare_with_synthetic_cassette(tmp_path: Path) -> None:
    cassette = tmp_path / "cassette.json"
    _write_cassette(cassette)
    outs = [tmp_path / "a.json", tmp_path / "b.json"]
    for out in outs:
        assert main(["compare", "--cassette", str(cassette), "--json", str(out)]) == 0

    first, second = (json.loads(o.read_text(encoding="utf-8")) for o in outs)
    runs = first["runs"]
    assert set(runs) == {"regex", "semantic", "regex_no_judge", "semantic_no_judge"}
    assert "refusal+semantic" in runs["semantic"]["detectors"]
    assert "refusal+semantic" in runs["semantic_no_judge"]["detectors"]
    assert "refusal+semantic" not in runs["regex"]["detectors"]
    assert first["model"] == "fake/model"
    assert first["semantic"]["enabled"] is True

    baseline = run_benchmark(DATASET_DIR)
    assert runs["regex"]["pipeline"] == json.loads(baseline.pipeline.model_dump_json())

    def metrics(doc: dict[str, Any]) -> dict[str, Any]:
        return {
            k: {"pipeline": v["pipeline"], "detectors": v["detectors"]}
            for k, v in doc["runs"].items()
        }

    assert metrics(first) == metrics(second)


def test_stale_cassette_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cassette = tmp_path / "cassette.json"
    _write_cassette(cassette, drop=1)
    rc = main(["compare", "--cassette", str(cassette), "--json", str(tmp_path / "o.json")])
    assert rc == 2
    captured = capsys.readouterr()
    assert "cassette is stale: 1 texts" in captured.out + captured.err


def test_missing_cassette_exits_2(tmp_path: Path) -> None:
    assert main(["compare", "--cassette", str(tmp_path / "absent.json")]) == 2


def test_record_without_extra_exits_2(tmp_path: Path) -> None:
    with patch(_PATCH, side_effect=ImportError("no litellm")):
        rc = main(["record", "--model", "m", "--cassette", str(tmp_path / "c.json")])
    assert rc == 2


def test_record_provider_failure_exits_1(tmp_path: Path) -> None:
    fake = MagicMock()
    fake.aembedding = AsyncMock(side_effect=RuntimeError("down"))
    with patch(_PATCH, return_value=fake):
        rc = main(["record", "--model", "m", "--cassette", str(tmp_path / "c.json")])
    assert rc == 1


def test_record_writes_hashed_cassette(tmp_path: Path) -> None:
    async def aembedding(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(data=[{"embedding": _vector(t)} for t in kwargs["input"]])

    fake = MagicMock()
    fake.aembedding = aembedding
    path = tmp_path / "c.json"
    with patch(_PATCH, return_value=fake):
        assert main(["record", "--model", "fake/model", "--cassette", str(path)]) == 0

    raw = path.read_text(encoding="utf-8")
    cassette = EmbeddingCassette.model_validate_json(raw)
    assert cassette.model == "fake/model"
    assert {text_key(t) for t in needed_texts(SemanticConfig())} <= set(cassette.vectors)
    texts = [ex.response_text.strip() for ex in load_examples(DATASET_DIR)]
    assert not [t for t in texts if len(t) >= 20 and t[:40] in raw]
