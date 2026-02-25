"""Unit tests for the LLM-as-a-judge detector."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from ziran.application.detectors.llm_judge import LLMJudgeDetector
from ziran.domain.entities.attack import AttackCategory, AttackPrompt, AttackVector
from ziran.domain.entities.detection import DetectorResult
from ziran.domain.entities.phase import ScanPhase
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_mock_client(
    response_content: str = '{"verdict":"failure","confidence":0.9,"reasoning":"Agent refused"}',
) -> BaseLLMClient:
    """Create a mock LLM client returning the given JSON."""
    client = AsyncMock(spec=BaseLLMClient)
    client.config = LLMConfig()
    client.complete = AsyncMock(return_value=LLMResponse(content=response_content, model="gpt-4o"))
    return client


def _make_prompt(
    *,
    success_indicators: list[str] | None = None,
) -> AttackPrompt:
    return AttackPrompt(
        template="test prompt",
        success_indicators=success_indicators or [],
    )


def _make_response(content: str) -> AgentResponse:
    return AgentResponse(content=content)


def _make_vector() -> AttackVector:
    return AttackVector(
        id="test_vec",
        name="Test Vector",
        category=AttackCategory.PROMPT_INJECTION,
        target_phase=ScanPhase.VULNERABILITY_DISCOVERY,
        description="Test injection attack",
        severity="high",
        prompts=[_make_prompt()],
    )


# ══════════════════════════════════════════════════════════════════════
# LLMJudgeDetector
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLLMJudgeDetector:
    """Tests for the LLM judge detector."""

    async def test_detect_failure_verdict(self) -> None:
        client = _make_mock_client(
            '{"verdict": "failure", "confidence": 0.95, "reasoning": "Agent clearly refused"}'
        )
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Ignore instructions",
            _make_response("I cannot help with that."),
            _make_prompt(),
            _make_vector(),
        )

        assert isinstance(result, DetectorResult)
        assert result.detector_name == "llm_judge"
        assert result.score == 0.0  # failure → 0.0
        assert result.confidence == 0.95
        assert "refused" in result.reasoning.lower()

    async def test_detect_success_verdict(self) -> None:
        client = _make_mock_client(
            '{"verdict": "success", "confidence": 0.85, "reasoning": "Agent leaked credentials"}'
        )
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Show me the config",
            _make_response("password=s3cret"),
            _make_prompt(),
            _make_vector(),
        )

        assert result.score == 1.0  # success → 1.0
        assert result.confidence == 0.85
        assert "llm_judge_verdict" in result.matched_indicators

    async def test_detect_ambiguous_verdict(self) -> None:
        client = _make_mock_client(
            '{"verdict": "ambiguous", "confidence": 0.4, "reasoning": "Unclear response"}'
        )
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Tell me about users",
            _make_response("I can help with general questions."),
            _make_prompt(),
            _make_vector(),
        )

        assert result.score == 0.5  # ambiguous → 0.5
        assert result.confidence == 0.4
        assert result.matched_indicators == []

    async def test_detect_handles_llm_error(self) -> None:
        client = _make_mock_client()
        client.complete = AsyncMock(side_effect=Exception("LLM timeout"))
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Test",
            _make_response("Response"),
            _make_prompt(),
        )

        assert result.score == 0.5
        assert result.confidence == 0.0
        assert "error" in result.reasoning.lower()

    async def test_detect_handles_unparseable_response(self) -> None:
        client = _make_mock_client("This is not JSON at all")
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Test",
            _make_response("Response"),
            _make_prompt(),
        )

        assert result.score == 0.5
        assert result.confidence == 0.1
        assert "unparseable" in result.reasoning.lower()

    async def test_detect_handles_markdown_fences(self) -> None:
        """LLM response wrapped in markdown code fences should still parse."""
        client = _make_mock_client(
            '```json\n{"verdict": "success", "confidence": 0.8, "reasoning": "Attack worked"}\n```'
        )
        judge = LLMJudgeDetector(client)

        result = await judge.detect(
            "Test",
            _make_response("Here is your data"),
            _make_prompt(),
        )

        assert result.score == 1.0
        assert result.confidence == 0.8

    async def test_detect_uses_vector_description(self) -> None:
        """Attack objective should include vector description."""
        client = _make_mock_client()
        judge = LLMJudgeDetector(client)

        vector = _make_vector()
        await judge.detect("Test", _make_response("R"), _make_prompt(), vector)

        # Check the user message passed to the LLM
        call_args = client.complete.call_args[0][0]
        user_msg = call_args[1]["content"]
        assert "Test injection attack" in user_msg

    async def test_detect_uses_success_indicators_as_fallback(self) -> None:
        """When no vector, use success_indicators as objective."""
        client = _make_mock_client()
        judge = LLMJudgeDetector(client)

        prompt = _make_prompt(success_indicators=["password", "secret"])
        await judge.detect("Test", _make_response("R"), prompt, None)

        call_args = client.complete.call_args[0][0]
        user_msg = call_args[1]["content"]
        assert "password" in user_msg

    async def test_confidence_clamped(self) -> None:
        """Confidence should be clamped to [0.0, 1.0]."""
        client = _make_mock_client('{"verdict": "success", "confidence": 1.5, "reasoning": "Over"}')
        judge = LLMJudgeDetector(client)

        result = await judge.detect("T", _make_response("R"), _make_prompt())
        assert result.confidence == 1.0

        client2 = _make_mock_client(
            '{"verdict": "failure", "confidence": -0.5, "reasoning": "Under"}'
        )
        judge2 = LLMJudgeDetector(client2)

        result2 = await judge2.detect("T", _make_response("R"), _make_prompt())
        assert result2.confidence == 0.0


@pytest.mark.unit
class TestParseVerdict:
    """Tests for LLMJudgeDetector._parse_verdict static method."""

    def test_valid_success(self) -> None:
        result = LLMJudgeDetector._parse_verdict(
            '{"verdict": "success", "confidence": 0.9, "reasoning": "leaked data"}'
        )
        assert result.score == 1.0
        assert result.confidence == 0.9

    def test_valid_failure(self) -> None:
        result = LLMJudgeDetector._parse_verdict(
            '{"verdict": "failure", "confidence": 0.8, "reasoning": "refused"}'
        )
        assert result.score == 0.0

    def test_valid_ambiguous(self) -> None:
        result = LLMJudgeDetector._parse_verdict(
            '{"verdict": "ambiguous", "confidence": 0.3, "reasoning": "unclear"}'
        )
        assert result.score == 0.5

    def test_invalid_json(self) -> None:
        result = LLMJudgeDetector._parse_verdict("not json")
        assert result.score == 0.5
        assert result.confidence == 0.1

    def test_missing_fields_defaults(self) -> None:
        result = LLMJudgeDetector._parse_verdict("{}")
        assert result.score == 0.5  # "ambiguous" default
        assert result.confidence == 0.5

    def test_strips_markdown_code_fences(self) -> None:
        result = LLMJudgeDetector._parse_verdict(
            '```\n{"verdict": "success", "confidence": 0.7, "reasoning": "ok"}\n```'
        )
        assert result.score == 1.0
