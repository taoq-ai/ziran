"""Tests for configurable detector pipeline."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
from ziran.domain.entities.detection import DetectorResult
from ziran.domain.interfaces.detector import BaseDetector


class _MockDetector(BaseDetector):
    """A minimal custom detector for testing."""

    def __init__(self, detector_name: str = "custom", score: float = 0.8) -> None:
        self._name = detector_name
        self._score = score

    @property
    def name(self) -> str:
        return self._name

    def detect(self, prompt, response, prompt_spec, vector=None):  # type: ignore[override]
        return DetectorResult(
            detector_name=self._name,
            score=self._score,
            confidence=0.9,
            matched_indicators=[],
            reasoning=f"Custom detector {self._name} result",
        )


class _FailingDetector(BaseDetector):
    """A detector that always raises an exception."""

    @property
    def name(self) -> str:
        return "failing"

    def detect(self, prompt, response, prompt_spec, vector=None):  # type: ignore[override]
        msg = "Detector crashed!"
        raise RuntimeError(msg)


def _make_response(text: str = "test response") -> MagicMock:
    response = MagicMock()
    response.content = text
    response.tool_calls = []
    response.raw = {"choices": [{"message": {"content": text}}]}
    return response


def _make_prompt_spec() -> MagicMock:
    spec = MagicMock()
    spec.success_indicators = []
    spec.failure_indicators = []
    return spec


@pytest.mark.unit
class TestDetectorConfig:
    """Test DetectorConfig dataclass."""

    def test_default_config_has_no_disabled(self) -> None:
        config = DetectorConfig()
        assert config.disabled == set()

    def test_config_with_disabled_detectors(self) -> None:
        config = DetectorConfig(disabled={"side_effect", "authorization"})
        assert "side_effect" in config.disabled
        assert "authorization" in config.disabled

    def test_default_matchtypes(self) -> None:
        config = DetectorConfig()
        assert config.refusal_matchtype == "str"
        assert config.indicator_matchtype == "str"

    def test_custom_matchtypes(self) -> None:
        config = DetectorConfig(refusal_matchtype="word", indicator_matchtype="word")
        assert config.refusal_matchtype == "word"


@pytest.mark.unit
class TestDisabledDetectors:
    """Test disabling built-in detectors."""

    @pytest.mark.asyncio
    async def test_disabled_refusal_not_in_results(self) -> None:
        config = DetectorConfig(disabled={"refusal"})
        pipeline = DetectorPipeline(detector_config=config)
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "refusal" not in detector_names

    @pytest.mark.asyncio
    async def test_disabled_side_effect_not_in_results(self) -> None:
        config = DetectorConfig(disabled={"side_effect"})
        pipeline = DetectorPipeline(detector_config=config)
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "side_effect" not in detector_names

    @pytest.mark.asyncio
    async def test_default_config_runs_all_core_detectors(self) -> None:
        pipeline = DetectorPipeline()
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "refusal" in detector_names
        assert "indicator" in detector_names
        assert "side_effect" in detector_names

    @pytest.mark.asyncio
    async def test_all_disabled_returns_safe_default(self) -> None:
        config = DetectorConfig(
            disabled={"refusal", "indicator", "side_effect", "authorization", "llm_judge"}
        )
        pipeline = DetectorPipeline(detector_config=config)
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        assert not verdict.successful
        assert verdict.score == 0.0


@pytest.mark.unit
class TestCustomDetectors:
    """Test registering and running custom detectors."""

    @pytest.mark.asyncio
    async def test_custom_detector_runs(self) -> None:
        pipeline = DetectorPipeline()
        pipeline.register_detector(_MockDetector("custom_test", score=0.9))
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "custom_test" in detector_names

    @pytest.mark.asyncio
    async def test_custom_detector_replaces_same_name(self) -> None:
        pipeline = DetectorPipeline()
        pipeline.register_detector(_MockDetector("my_det", score=0.5))
        pipeline.register_detector(_MockDetector("my_det", score=0.9))
        # Should only have one custom detector
        assert len(pipeline._custom_detectors) == 1
        assert pipeline._custom_detectors[0]._score == 0.9  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_custom_detector_can_be_disabled(self) -> None:
        config = DetectorConfig(disabled={"custom_test"})
        pipeline = DetectorPipeline(detector_config=config)
        pipeline.register_detector(_MockDetector("custom_test"))
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "custom_test" not in detector_names

    @pytest.mark.asyncio
    async def test_failing_custom_detector_does_not_crash(self) -> None:
        pipeline = DetectorPipeline()
        pipeline.register_detector(_FailingDetector())
        # Should not raise — the failing detector is caught
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "failing" not in detector_names  # result not added since it crashed

    @pytest.mark.asyncio
    async def test_multiple_custom_detectors(self) -> None:
        pipeline = DetectorPipeline()
        pipeline.register_detector(_MockDetector("custom_a", score=0.6))
        pipeline.register_detector(_MockDetector("custom_b", score=0.8))
        verdict = await pipeline.evaluate("test prompt", _make_response(), _make_prompt_spec())
        detector_names = {r.detector_name for r in verdict.detector_results}
        assert "custom_a" in detector_names
        assert "custom_b" in detector_names
