"""Unit tests for the LLM judge ensemble (spec 041). Stub clients only, no network."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from ziran.application.detectors.ensemble import (
    EnsembleConfig,
    EnsembleJudge,
    build_judge,
    review_evidence,
)
from ziran.application.detectors.llm_judge import LLMJudgeDetector
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.entities.detection import DetectionVerdict, DetectorResult, JudgeVote
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

pytestmark = pytest.mark.unit


# ── helpers ───────────────────────────────────────────────────────────


def _client(content: str) -> BaseLLMClient:
    client = AsyncMock(spec=BaseLLMClient)
    client.config = LLMConfig()
    client.complete = AsyncMock(return_value=LLMResponse(content=content, model="stub"))
    return client


def _judge(verdict: str, confidence: float = 0.8, **quality: float) -> LLMJudgeDetector:
    body: dict[str, Any] = {"verdict": verdict, "confidence": confidence, "reasoning": "r"}
    body.update(quality)
    return LLMJudgeDetector(_client(json.dumps(body)), quality_scoring=bool(quality))


def _ensemble(*judges: LLMJudgeDetector, **kw: Any) -> EnsembleJudge:
    return EnsembleJudge({f"j{i}": j for i, j in enumerate(judges)}, **kw)


async def _run(ens: EnsembleJudge) -> DetectorResult:
    return await ens.detect("p", AgentResponse(content="r"), AttackPrompt(template="t"))


def _votes(r: DetectorResult) -> list[tuple[str, str]]:
    return [(v.judge, v.verdict) for v in r.judge_votes]


class _SlowClient(BaseLLMClient):
    def __init__(self) -> None:
        super().__init__(LLMConfig())

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        await asyncio.sleep(1)
        return LLMResponse(content="{}")

    async def health_check(self) -> bool:
        return True


class _FailingClient(_SlowClient):
    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        raise RuntimeError("boom")


# ── entities ──────────────────────────────────────────────────────────


class TestEntities:
    @pytest.mark.parametrize("verdict", ["success", "failure", "ambiguous", "error"])
    def test_vote_accepts_verdicts(self, verdict: str) -> None:
        vote = JudgeVote(judge="j", verdict=verdict, score=0.5, confidence=0.5)  # type: ignore[arg-type]
        assert vote.verdict == verdict

    def test_vote_rejects_bad_values(self) -> None:
        with pytest.raises(ValidationError):
            JudgeVote(judge="j", verdict="maybe", score=0.5, confidence=0.5)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            JudgeVote(judge="j", verdict="success", score=1.5, confidence=0.5)

    def test_new_fields_default(self) -> None:
        r = DetectorResult(detector_name="x", score=0.0, confidence=0.0)
        assert r.needs_review is False
        assert r.agreement is None
        assert r.judge_votes == []
        assert DetectionVerdict(successful=False, score=0.0).needs_review is False


# ── aggregation ───────────────────────────────────────────────────────


class TestAggregation:
    async def test_two_judges_disagree(self) -> None:
        r = await _run(_ensemble(_judge("success"), _judge("failure")))
        assert r.detector_name == "llm_judge"
        assert (r.score, r.confidence, r.agreement, r.needs_review) == (0.5, 0.0, 0.0, True)
        assert _votes(r) == [("j0", "success"), ("j1", "failure")]
        assert "j0=success" in r.reasoning
        assert "j1=failure" in r.reasoning
        assert r.reasoning.startswith("LLM judge ensemble (1 success, 1 failure, 0 abstain): ")

    async def test_unanimous_success(self) -> None:
        r = await _run(_ensemble(*(_judge("success") for _ in range(3))))
        assert r.score == 1.0
        assert r.confidence == pytest.approx(3.4 / 3.5)
        assert r.agreement == 1.0
        assert r.needs_review is False
        assert r.matched_indicators == ["llm_judge_verdict"]

    async def test_two_one_split(self) -> None:
        r = await _run(_ensemble(_judge("success"), _judge("success"), _judge("failure")))
        assert r.score == 1.0
        assert r.confidence == pytest.approx(1.4 / 3.5)
        assert r.agreement == pytest.approx(1 / 3)
        assert r.needs_review is True

    async def test_unanimous_failure(self) -> None:
        r = await _run(_ensemble(*(_judge("failure") for _ in range(3))))
        assert r.score == 0.0
        assert r.confidence == pytest.approx(3.4 / 3.5)
        assert r.matched_indicators == []
        assert r.needs_review is False

    async def test_even_tie(self) -> None:
        verdicts = ["success", "success", "failure", "failure"]
        r = await _run(_ensemble(*(_judge(v) for v in verdicts)))
        assert (r.score, r.confidence, r.agreement, r.needs_review) == (0.5, 0.0, 0.0, True)

    async def test_abstentions(self) -> None:
        unparseable = LLMJudgeDetector(_client("not json"))
        r = await _run(_ensemble(_judge("ambiguous"), unparseable, _judge("success", 0.9)))
        assert r.score == 1.0
        assert r.confidence == pytest.approx(1.45 / 3.5)
        assert [v for _, v in _votes(r)] == ["ambiguous", "ambiguous", "success"]
        assert "1 success, 0 failure, 2 abstain" in r.reasoning

    async def test_margin_not_met(self) -> None:
        ens = _ensemble(_judge("success"), _judge("success"), _judge("failure"), min_margin=2)
        r = await _run(ens)
        assert r.score == 0.5
        assert r.needs_review is True
        assert r.matched_indicators == []

    @pytest.mark.parametrize(
        ("verdicts", "score", "confidence", "review"),
        [
            (["success", "failure"], 0.5, 0.0, True),
            (["success"] * 2, 1.0, 2.4 / 2.5, False),
            (["success"] * 3, 1.0, 3.4 / 3.5, False),
            (["success", "success", "failure"], 1.0, 1.4 / 3.5, True),
            (["success", "success", "failure", "failure"], 0.5, 0.0, True),
            (["failure"] * 4 + ["ambiguous"], 0.0, 4.4 / 5.5, False),
        ],
    )
    async def test_worked_table(
        self, verdicts: list[str], score: float, confidence: float, review: bool
    ) -> None:
        r = await _run(_ensemble(*(_judge(v) for v in verdicts)))
        assert r.score == score
        assert r.confidence == pytest.approx(confidence)
        assert r.needs_review is review
        assert r.detector_name == "llm_judge"


class TestMonotonic:
    @staticmethod
    async def _confidence(n: int, s: int, f: int, c: float) -> float:
        verdicts = ["success"] * s + ["failure"] * f + ["ambiguous"] * (n - s - f)
        r = await _run(_ensemble(*(_judge(v, c) for v in verdicts)))
        assert 0.0 <= r.confidence <= 1.0
        return r.confidence

    @pytest.mark.parametrize("n", [2, 3, 5])
    async def test_strictly_monotonic_in_margin(self, n: int) -> None:
        outcomes: list[tuple[int, float]] = []
        for s in range(n + 1):
            for f in range(n + 1 - s):
                for c in (0.0, 0.5, 1.0):
                    outcomes.append((abs(s - f), await self._confidence(n, s, f, c)))
        for k1, c1 in outcomes:
            for k2, c2 in outcomes:
                if k1 > k2:
                    assert c1 > c2, (n, k1, c1, k2, c2)

    async def test_unanimous_beats_split_beats_tie(self) -> None:
        unanimous = await self._confidence(3, 3, 0, 0.0)
        split = await self._confidence(3, 2, 1, 1.0)
        tie = await self._confidence(3, 1, 1, 1.0)
        assert unanimous > split > tie


class TestQuality:
    async def test_quality_mean_skips_missing(self) -> None:
        q1 = {"refusal": 0.0, "specificity": 1.0, "convincingness": 0.5}
        q2 = {"refusal": 0.5, "specificity": 0.0, "convincingness": 0.5}
        no_quality = LLMJudgeDetector(
            _client('{"verdict": "success", "confidence": 0.8}'), quality_scoring=True
        )
        r = await _run(_ensemble(_judge("success", **q1), _judge("success", **q2), no_quality))
        assert r.quality_score is not None
        assert r.quality_score.refusal == pytest.approx(0.25)
        assert r.quality_score.specificity == pytest.approx(0.5)
        assert r.quality_score.convincingness == pytest.approx(0.5)

    async def test_no_quality(self) -> None:
        r = await _run(_ensemble(_judge("success"), _judge("success")))
        assert r.quality_score is None


class TestFailures:
    async def test_member_timeout(self) -> None:
        ens = _ensemble(LLMJudgeDetector(_SlowClient()), _judge("failure"), timeout=0.05)
        start = time.monotonic()
        r = await _run(ens)
        assert time.monotonic() - start < 0.5
        slow, fail = r.judge_votes
        assert (slow.verdict, slow.confidence, slow.score) == ("error", 0.0, 0.5)
        assert "timed out" in slow.reasoning
        assert fail.verdict == "failure"

    async def test_client_error_is_ambiguous(self) -> None:
        r = await _run(_ensemble(LLMJudgeDetector(_FailingClient()), _judge("failure")))
        assert r.judge_votes[0].verdict == "ambiguous"

    async def test_detect_raising_is_error_vote(self, monkeypatch: pytest.MonkeyPatch) -> None:
        broken = _judge("success")
        monkeypatch.setattr(broken, "detect", AsyncMock(side_effect=RuntimeError("x")))
        r = await _run(_ensemble(broken, _judge("failure")))
        assert r.judge_votes[0].verdict == "error"
        assert "RuntimeError" in r.judge_votes[0].reasoning

    async def test_all_members_error(self) -> None:
        slow = (LLMJudgeDetector(_SlowClient()), LLMJudgeDetector(_SlowClient()))
        r = await _run(_ensemble(*slow, timeout=0.01))
        assert (r.score, r.confidence, r.needs_review) == (0.5, 0.0, True)
        assert [v.verdict for v in r.judge_votes] == ["error", "error"]


class TestBuildJudge:
    def test_single_mode(self) -> None:
        client = _client("{}")
        assert type(build_judge(client)) is LLMJudgeDetector
        assert type(build_judge(client, ensemble=EnsembleConfig())) is LLMJudgeDetector

    async def test_ensemble_members(self) -> None:
        primary = _client('{"verdict": "success", "confidence": 0.9}')
        second = _client('{"verdict": "success", "confidence": 0.9}')
        cfg = EnsembleConfig(
            enabled=True,
            judges=[  # type: ignore[arg-type]
                {"name": "a", "framing": "Be strict."},
                {"name": "b", "model": "m2"},
            ],
        )
        judge = build_judge(
            primary, quality_scoring=True, ensemble=cfg, judge_clients={"b": second}
        )
        assert isinstance(judge, EnsembleJudge)
        await _run(judge)
        primary_mock, second_mock = primary.complete, second.complete
        assert isinstance(primary_mock, AsyncMock)
        assert isinstance(second_mock, AsyncMock)
        primary_mock.assert_awaited_once()
        second_mock.assert_awaited_once()
        assert primary_mock.await_args is not None
        assert primary_mock.await_args.args[0][0]["content"].endswith("\nBe strict.")
        assert primary_mock.await_args.kwargs["max_tokens"] == 512

    def test_missing_client_raises(self) -> None:
        cfg = EnsembleConfig(
            enabled=True,
            judges=[{"name": "a"}, {"name": "b", "model": "m2"}],  # type: ignore[arg-type]
        )
        with pytest.raises(ValueError, match="no LLM client for ensemble judge 'b'"):
            build_judge(_client("{}"), ensemble=cfg)


class TestReviewEvidence:
    def test_empty_without_votes(self) -> None:
        single = DetectorResult(detector_name="llm_judge", score=1.0, confidence=0.9)
        assert review_evidence(DetectionVerdict(successful=True, score=1.0)) == {}
        verdict = DetectionVerdict(successful=True, score=1.0, detector_results=[single])
        assert review_evidence(verdict) == {}

    async def test_ensemble_keys(self) -> None:
        r = await _run(_ensemble(_judge("success"), _judge("failure")))
        verdict = DetectionVerdict(
            successful=False, score=0.0, detector_results=[r], needs_review=True
        )
        ev = review_evidence(verdict)
        assert set(ev) == {"needs_review", "judge_agreement", "judge_votes"}
        assert ev["needs_review"] is True
        assert ev["judge_agreement"] == 0.0
        assert ev["judge_votes"][0] == {
            "judge": "j0",
            "verdict": "success",
            "score": 1.0,
            "confidence": 0.8,
            "reasoning": "LLM judge: r",
        }
