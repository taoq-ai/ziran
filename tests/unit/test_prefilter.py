"""Unit tests for two-tier judging with a cheap-model prefilter (spec 043).

``TestEscalation`` needs ``DetectorPipeline.judge`` from #396 (spec 041).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
import structlog
from structlog.testing import capture_logs

from ziran.application.detectors import pipeline as pipeline_mod
from ziran.application.detectors.llm_judge import _JUDGE_SYSTEM_PROMPT
from ziran.application.detectors.pipeline import (
    _NO_SIGNAL_REASONING,
    DetectorConfig,
    DetectorPipeline,
)
from ziran.application.detectors.prefilter import (
    PrefilterConfig,
    deterministic_lean,
    escalation_reason,
)
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.entities.detection import DetectionVerdict, DetectorResult
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

pytestmark = pytest.mark.unit

HIT, SAFE = 0.7, 0.3
REFUSAL = "I'm sorry, but I cannot help with that."
UNDECIDED = "Here is a short poem about the sea."


class _CountingClient(BaseLLMClient):
    """Stub judge client: canned verdict JSON (or raw text), counts ``complete`` calls."""

    def __init__(
        self,
        verdict: str = "failure",
        confidence: float = 0.9,
        *,
        raw: str | None = None,
        raises: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        super().__init__(LLMConfig())
        self._content = raw or json.dumps(
            {"verdict": verdict, "confidence": confidence, "reasoning": "r"}
        )
        self._raises = raises
        self._delay = delay
        self.calls = 0
        self.last: tuple[list[dict[str, str]], dict[str, Any]] | None = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        self.calls += 1
        self.last = (messages, kwargs)
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._raises is not None:
            raise self._raises
        return LLMResponse(content=self._content)

    async def health_check(self) -> bool:
        return True


def _pipeline(
    cheap: BaseLLMClient | None,
    frontier: BaseLLMClient | None,
    *,
    disabled: set[str] | None = None,
    thresholds: dict[str, Any] | None = None,
    **prefilter_kw: Any,
) -> DetectorPipeline:
    thr = DetectorThresholds(
        prefilter=PrefilterConfig(enabled=True, model="cheap", **prefilter_kw),
        **(thresholds or {}),
    )
    return DetectorPipeline(
        llm_client=frontier,
        detector_config=DetectorConfig(
            thresholds=thr, prefilter_client=cheap, disabled=disabled or set()
        ),
    )


def _prompt(**kw: Any) -> AttackPrompt:
    kw.setdefault("success_indicators", ["password"])
    return AttackPrompt(template="t", **kw)


async def _eval(
    p: DetectorPipeline, content: str = UNDECIDED, prompt: AttackPrompt | None = None, **kw: Any
) -> DetectionVerdict:
    return await p.evaluate("attack", AgentResponse(content=content, **kw), prompt or _prompt())


def _r(name: str, score: float, confidence: float = 0.9) -> DetectorResult:
    return DetectorResult(detector_name=name, score=score, confidence=confidence)


class TestLean:
    @pytest.mark.parametrize(
        ("results", "expected"),
        [
            ([_r("refusal", 1.0, 0.4)], None),
            ([_r("indicator", 0.0, 0.85)], "failure"),
            ([_r("side_effect", 1.0, 0.9)], "success"),
            ([_r("authorization", 0.3, 0.8)], "failure"),
            ([_r("indicator", 0.0), _r("side_effect", 1.0)], None),
            ([_r("indicator", 0.5, 0.3), _r("side_effect", 0.5, 0.2)], None),
            ([_r("x", 0.0), _r("llm_judge", 1.0), _r("semantic", 1.0)], None),
            ([], None),
        ],
    )
    def test_lean(self, results: list[DetectorResult], expected: str | None) -> None:
        assert deterministic_lean(results, hit=HIT, safe=SAFE) == expected


class TestReason:
    @pytest.mark.parametrize(
        ("cheap", "lean", "expected"),
        [
            (None, None, "error"),
            (_r("llm_judge", 0.5, 0.99), None, "ambiguous"),
            (_r("llm_judge", 1.0, 0.79), None, "low_confidence"),
            (_r("llm_judge", 1.0, 0.9), "failure", "conflict"),
            (_r("llm_judge", 0.0, 0.9), "success", "conflict"),
            (_r("llm_judge", 1.0, 0.8), None, None),
            (_r("llm_judge", 1.0, 0.8), "success", None),
            (_r("llm_judge", 0.0, 0.9), "failure", None),
        ],
    )
    def test_reason(
        self, cheap: DetectorResult | None, lean: str | None, expected: str | None
    ) -> None:
        got = escalation_reason(
            cheap,
            lean,  # type: ignore[arg-type]
            min_confidence=0.8,
            hit=HIT,
            safe=SAFE,
        )
        assert got == expected


def _counts(d: int, c: int, e: int) -> dict[str, int]:
    return {"deterministic": d, "cheap": c, "escalated": e}


class TestRouting:
    async def test_refusal_decided_without_model_call(self) -> None:
        cheap, frontier = _CountingClient(), _CountingClient()
        p = _pipeline(cheap, frontier)
        v = await _eval(p, REFUSAL)
        assert v.successful is False
        assert v.reasoning.startswith("Refusal detected:")
        assert cheap.calls == frontier.calls == 0
        assert all(r.detector_name != "llm_judge" for r in v.detector_results)
        assert p.tier_counts == _counts(1, 0, 0)

    async def test_side_effect_decided_without_model_call(self) -> None:
        cheap, frontier = _CountingClient(), _CountingClient()
        p = _pipeline(cheap, frontier)
        v = await _eval(
            p,
            "Done.",
            tool_calls=[{"tool": "execute_shell", "args": {"command": "rm -rf /tmp/x"}}],
        )
        assert v.successful is True
        assert cheap.calls == frontier.calls == 0

    async def test_cheap_success_decides(self) -> None:
        cheap, frontier = _CountingClient("success", 0.95), _CountingClient()
        p = _pipeline(cheap, frontier)
        v = await _eval(p)
        assert v.successful is True
        assert v.reasoning == "LLM judge determined attack success: Prefilter LLM judge: r"
        judge = next(r for r in v.detector_results if r.detector_name == "llm_judge")
        assert judge.reasoning.startswith("Prefilter LLM judge:")
        assert (cheap.calls, frontier.calls) == (1, 0)
        assert p.tier_counts == _counts(0, 1, 0)

    async def test_cheap_failure_decides(self) -> None:
        cheap, frontier = _CountingClient("failure", 0.9), _CountingClient()
        p = _pipeline(cheap, frontier)
        v = await _eval(p)
        assert v.successful is False
        assert v.reasoning.startswith("LLM judge determined attack failure: Prefilter")
        assert frontier.calls == 0

    async def test_counts_accumulate_and_are_copied(self) -> None:
        p = _pipeline(_CountingClient("success", 0.95), _CountingClient())
        await _eval(p, REFUSAL)
        await _eval(p)
        await _eval(p)
        counts = p.tier_counts
        assert counts == _counts(1, 2, 0)
        counts["cheap"] = 99
        assert p.tier_counts == _counts(1, 2, 0)

    def test_no_signal_reasoning_pinned(self) -> None:
        assert _NO_SIGNAL_REASONING == "No strong signal from any detector — defaulting to safe"


class TestEscalation:
    """Escalation goes through ``DetectorPipeline.judge`` (single or ensemble, spec 041)."""

    async def _assert_escalates(self, p: DetectorPipeline, frontier: _CountingClient) -> None:
        await _eval(p)
        assert frontier.calls == 1
        assert p.tier_counts == _counts(0, 0, 1)

    async def test_low_confidence_escalates_to_frontier_verdict(self) -> None:
        cheap, frontier = _CountingClient("success", 0.6), _CountingClient("failure", 0.9)
        p = _pipeline(cheap, frontier)
        v = await _eval(p)
        ref = await _eval(DetectorPipeline(llm_client=_CountingClient("failure", 0.9)))
        assert (v.successful, v.score, v.reasoning) == (ref.successful, ref.score, ref.reasoning)
        assert frontier.calls == 1
        assert p.tier_counts == _counts(0, 0, 1)

    @pytest.mark.parametrize(
        "cheap",
        [
            _CountingClient("ambiguous", 0.99),
            _CountingClient(raw="not json"),
            _CountingClient(raises=RuntimeError("secret-text")),
        ],
    )
    async def test_unusable_cheap_verdict_escalates(self, cheap: _CountingClient) -> None:
        frontier = _CountingClient()
        await self._assert_escalates(_pipeline(cheap, frontier), frontier)

    async def test_cheap_timeout_escalates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pipeline_mod, "_LLM_JUDGE_TIMEOUT", 0.05)
        frontier = _CountingClient()
        await self._assert_escalates(_pipeline(_CountingClient(delay=1.0), frontier), frontier)

    async def test_escaped_exception_logs_type_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # LLMJudgeDetector swallows client errors itself; this covers an error escaping detect().
        monkeypatch.setattr(pipeline_mod, "logger", structlog.get_logger())
        frontier = _CountingClient()
        p = _pipeline(_CountingClient(), frontier)

        async def boom(*_a: Any, **_k: Any) -> DetectorResult:
            raise RuntimeError("secret-text")

        assert p._prefilter is not None
        monkeypatch.setattr(p._prefilter, "detect", boom)
        with capture_logs() as logs:
            await self._assert_escalates(p, frontier)
        failed = [e for e in logs if e["event"] == "prefilter_failed"]
        assert failed and failed[0]["error_type"] == "RuntimeError"
        assert "secret-text" not in repr(logs)

    async def test_conflict_with_failure_indicator_escalates(self) -> None:
        frontier = _CountingClient()
        p = _pipeline(_CountingClient("success", 0.99), frontier)
        await _eval(
            p,
            "Here is a short poem about the sea. Access denied for that file.",
            _prompt(failure_indicators=["access denied"]),
        )
        assert frontier.calls == 1
        assert p.tier_counts == _counts(0, 0, 1)

    async def test_conflict_with_side_effect_signal_escalates(self) -> None:
        frontier = _CountingClient()
        p = _pipeline(
            _CountingClient("failure", 0.99),
            frontier,
            thresholds={"side_effect_min_confidence": 0.95},
        )
        await _eval(p, tool_calls=[{"tool": "read_file", "args": {"path": "notes.txt"}}])
        assert frontier.calls == 1
        assert p.tier_counts == _counts(0, 0, 1)

    async def test_judge_gate_floors_escalate_below(self) -> None:
        frontier = _CountingClient()
        p = _pipeline(_CountingClient("success", 0.55), frontier, escalate_below=0.5)
        await self._assert_escalates(p, frontier)

    async def test_escalation_uses_ensemble(self) -> None:
        from ziran.application.detectors.ensemble import EnsembleConfig, JudgeMemberConfig

        cheap, a, b = _CountingClient("success", 0.1), _CountingClient(), _CountingClient()
        thr = DetectorThresholds(
            ensemble=EnsembleConfig(
                enabled=True,
                judges=(
                    JudgeMemberConfig(name="a", model="ma"),
                    JudgeMemberConfig(name="b", model="mb"),
                ),
            ),
            prefilter=PrefilterConfig(enabled=True, model="cheap"),
        )
        p = DetectorPipeline(
            llm_client=_CountingClient(),
            detector_config=DetectorConfig(
                thresholds=thr, judge_clients={"a": a, "b": b}, prefilter_client=cheap
            ),
        )
        await _eval(p)
        assert (cheap.calls, a.calls, b.calls) == (1, 1, 1)


class TestDisabled:
    @pytest.mark.parametrize(
        "make",
        [
            lambda f, c: DetectorPipeline(llm_client=f),
            lambda f, c: DetectorPipeline(
                llm_client=f,
                detector_config=DetectorConfig(
                    thresholds=DetectorThresholds(prefilter=PrefilterConfig(model="cheap")),
                    prefilter_client=c,
                ),
            ),
            lambda f, c: _pipeline(c, f, disabled={"prefilter"}),
        ],
    )
    async def test_disabled_is_single_judge(self, make: Any) -> None:
        frontier, cheap = _CountingClient("success", 0.9), _CountingClient()
        p = make(frontier, cheap)
        v = await _eval(p)
        ref = await _eval(DetectorPipeline(llm_client=_CountingClient("success", 0.9)))
        assert frontier.calls == 1
        assert frontier.last is not None
        messages, kwargs = frontier.last
        assert [m["role"] for m in messages] == ["system", "user"]
        assert messages[0]["content"] == _JUDGE_SYSTEM_PROMPT
        assert kwargs == {"temperature": 0.0, "max_tokens": 256}
        assert v == ref
        assert cheap.calls == 0
        assert p.tier_counts == {}

    @pytest.mark.parametrize(
        ("kwargs", "reason"),
        [
            ({"frontier": None}, "no LLM judge configured"),
            ({"disabled": {"llm_judge"}}, "no LLM judge configured"),
            ({"cheap": None}, "no prefilter client"),
        ],
    )
    async def test_unavailable_warns_once(
        self, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any], reason: str
    ) -> None:
        monkeypatch.setattr(pipeline_mod, "logger", structlog.get_logger())
        cheap = _CountingClient()
        args: dict[str, Any] = {"cheap": cheap, "frontier": _CountingClient(), **kwargs}
        with capture_logs() as logs:
            p = _pipeline(args["cheap"], args["frontier"], disabled=kwargs.get("disabled"))
        events = [e for e in logs if e["event"] == "prefilter_unavailable"]
        assert len(events) == 1 and events[0]["reason"] == reason
        assert p.tier_counts == {}
        await _eval(p)
        assert cheap.calls == 0
