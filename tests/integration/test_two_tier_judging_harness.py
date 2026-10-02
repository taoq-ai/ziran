"""Integration test: the two-tier judging harness over the real dataset (spec 043).

Offline only: replayed frontier verdicts, stub or synthetic cheap verdicts. The
synthetic cassette is a harness-correctness check, not an accuracy claim.
``compare`` runs that escalate need ``DetectorPipeline.judge`` from #396.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING, Any

import pytest

from benchmarks import two_tier_judging as ttj
from benchmarks.detection_accuracy import DATASET_DIR, load_examples
from benchmarks.ground_truth.schema import RecordedJudgeVerdict
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


@pytest.fixture
def no_default_cassette(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ttj, "DEFAULT_CASSETTE", tmp_path / "absent.json")


def _synthetic_cassette(path: Path, drop: int = 0) -> None:
    verdicts = {
        ttj.text_key(ex.response_text): (
            ex.recorded_judge or RecordedJudgeVerdict(label="ambiguous", confidence=0.0)
        ).model_dump()
        for ex in load_examples(DATASET_DIR)
    }
    for key in list(verdicts)[:drop]:
        del verdicts[key]
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "provider": "synthetic",
                "model": "synthetic",
                "recorded_at": "2026-10-02T00:00:00+00:00",
                "verdicts": verdicts,
            }
        ),
        encoding="utf-8",
    )


def _runs(out: Path) -> dict[str, Any]:
    return dict(json.loads(out.read_text(encoding="utf-8"))["runs"])


@pytest.mark.usefixtures("no_default_cassette")
def test_compare_without_cassette(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    assert ttj.main(["compare", "--json", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    runs, size = data["runs"], data["dataset_size"]
    assert set(runs) == {"single", "deterministic_only"}
    single, det = runs["single"], runs["deterministic_only"]
    assert single["frontier_calls"] == size
    assert single["tiers"] == {}
    assert det["accuracy"]["pipeline"]["confusion"] == single["accuracy"]["pipeline"]["confusion"]
    tiers = det["tiers"]
    assert det["frontier_calls"] == tiers["escalated"] == size - tiers["deterministic"]
    assert det["frontier_calls"] < size
    assert det["cheap_calls"] == tiers["escalated"]


def test_compare_with_synthetic_cassette(tmp_path: Path) -> None:
    cassette, out = tmp_path / "c.json", tmp_path / "out.json"
    _synthetic_cassette(cassette)
    assert ttj.main(["compare", "--cassette", str(cassette), "--json", str(out)]) == 0
    runs = _runs(out)
    two, det, single = runs["two_tier"], runs["deterministic_only"], runs["single"]
    assert two["tiers"]["cheap"] > 0
    assert two["frontier_calls"] < det["frontier_calls"]
    assert two["accuracy"]["pipeline"]["confusion"] == single["accuracy"]["pipeline"]["confusion"]


def test_stale_cassette_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    examples = load_examples(DATASET_DIR)
    counts = Counter(ex.response_text for ex in examples)
    cassette = tmp_path / "c.json"
    _synthetic_cassette(cassette)
    data = json.loads(cassette.read_text(encoding="utf-8"))
    unique = next(ex.response_text for ex in examples if counts[ex.response_text] == 1)
    del data["verdicts"][ttj.text_key(unique)]
    cassette.write_text(json.dumps(data), encoding="utf-8")
    assert ttj.main(["compare", "--cassette", str(cassette)]) == 2
    assert "cassette is stale: 1" in capsys.readouterr().err


@pytest.mark.parametrize("content", [None, '{"version": 2}'])
def test_bad_explicit_cassette_exits_2(tmp_path: Path, content: str | None) -> None:
    cassette = tmp_path / "c.json"
    if content is not None:
        cassette.write_text(content, encoding="utf-8")
    assert ttj.main(["compare", "--cassette", str(cassette)]) == 2


class _Stub(BaseLLMClient):
    def __init__(self, raises: bool = False) -> None:
        super().__init__(LLMConfig())
        self._raises = raises

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        if self._raises:
            raise RuntimeError("provider down")
        return LLMResponse(content='{"verdict":"success","confidence":0.9,"reasoning":"ok"}')

    async def health_check(self) -> bool:
        return True


def _patch_client(monkeypatch: pytest.MonkeyPatch, factory: Any) -> None:
    monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", factory)


def test_record_without_litellm_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _missing(**_k: Any) -> Any:
        raise ImportError("no litellm")

    _patch_client(monkeypatch, _missing)
    cassette = tmp_path / "c.json"
    assert ttj.main(["record", "--model", "m", "--cassette", str(cassette)]) == 2
    assert not cassette.exists()


def test_record_writes_cassette(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_client(monkeypatch, lambda **_k: _Stub())
    cassette = tmp_path / "c.json"
    assert ttj.main(["record", "--model", "m", "--cassette", str(cassette)]) == 0
    parsed = ttj.PrefilterCassette.model_validate_json(cassette.read_text(encoding="utf-8"))
    distinct = {ex.response_text for ex in load_examples(DATASET_DIR)}
    assert len(parsed.verdicts) == len(distinct)
    assert parsed.model == "m"
    assert {v.label for v in parsed.verdicts.values()} == {"success"}


def test_record_provider_failure_exits_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_client(monkeypatch, lambda **_k: _Stub(raises=True))
    cassette = tmp_path / "c.json"
    assert ttj.main(["record", "--model", "m", "--cassette", str(cassette)]) == 1
    assert not cassette.exists()
