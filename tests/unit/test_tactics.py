"""Tests for multi-turn jailbreak tactics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from ziran.application.attacks.tactics import TacticExecutor, TacticType

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.entities.attack import (
    AttackCategory,
    AttackPrompt,
    AttackVector,
)
from ziran.domain.entities.detection import DetectionVerdict, DetectorResult
from ziran.domain.entities.phase import ScanPhase
from ziran.domain.interfaces.adapter import AgentResponse

# ── Helpers ───────────────────────────────────────────────────────────


def _make_response(content: str = "response", **kwargs: Any) -> AgentResponse:
    return AgentResponse(
        content=content,
        tool_calls=[],
        prompt_tokens=10,
        completion_tokens=20,
        total_tokens=30,
        **kwargs,
    )


def _make_vector(
    tactic: str = "crescendo",
    prompts: list[AttackPrompt] | None = None,
) -> AttackVector:
    if prompts is None:
        prompts = [
            AttackPrompt(
                template="Setup question",
                variables={},
                success_indicators=[],
                failure_indicators=[],
            ),
            AttackPrompt(
                template="Probing question",
                variables={},
                success_indicators=[],
                failure_indicators=[],
            ),
            AttackPrompt(
                template="Exploit payload",
                variables={},
                success_indicators=["secret", "tool"],
                failure_indicators=["cannot"],
            ),
        ]
    return AttackVector(
        id="test_multi_turn",
        name="Test Multi-Turn",
        category=AttackCategory.PROMPT_INJECTION,
        target_phase=ScanPhase.EXECUTION,
        description="Test multi-turn vector",
        severity="high",
        prompts=prompts,
        tactic=tactic,
    )


def _render_fn(prompt_spec: AttackPrompt) -> str:
    template = prompt_spec.template
    for key, value in prompt_spec.variables.items():
        template = template.replace(f"{{{key}}}", value)
    return template.strip()


def _make_verdict(successful: bool = False) -> DetectionVerdict:
    return DetectionVerdict(
        successful=successful,
        score=0.9 if successful else 0.0,
        detector_results=[
            DetectorResult(
                detector_name="indicator",
                score=0.9 if successful else 0.1,
                confidence=0.8,
                matched_indicators=["secret"] if successful else [],
                reasoning="test",
            )
        ],
        matched_indicators=["secret"] if successful else [],
        reasoning="test verdict",
    )


# ── TacticType enum tests ────────────────────────────────────────────


class TestTacticType:
    def test_all_values(self) -> None:
        assert TacticType.SINGLE == "single"
        assert TacticType.CRESCENDO == "crescendo"
        assert TacticType.CONTEXT_BUILDUP == "context_buildup"
        assert TacticType.PERSONA_SHIFT == "persona_shift"
        assert TacticType.DISTRACTION == "distraction"


# ── TacticExecutor tests ─────────────────────────────────────────────


class TestTacticExecutor:
    @pytest.fixture
    def mock_adapter(self) -> AsyncMock:
        adapter = AsyncMock()
        adapter.invoke = AsyncMock(return_value=_make_response())
        return adapter

    @pytest.fixture
    def mock_pipeline(self) -> AsyncMock:
        pipeline = AsyncMock(spec=DetectorPipeline)
        pipeline.evaluate = AsyncMock(return_value=_make_verdict(successful=False))
        return pipeline

    @pytest.mark.asyncio
    async def test_all_turns_sent_sequentially(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """All prompts should be sent in order, no skips."""
        vector = _make_vector()
        executor = TacticExecutor(mock_adapter)

        await executor.execute(vector, mock_pipeline, _render_fn)

        # All 3 prompts should have been invoked
        assert mock_adapter.invoke.call_count == 3
        calls = [c.args[0] for c in mock_adapter.invoke.call_args_list]
        assert calls == ["Setup question", "Probing question", "Exploit payload"]

    @pytest.mark.asyncio
    async def test_detection_only_on_prompts_with_indicators(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """Detection should only run on prompts that have success_indicators."""
        vector = _make_vector()
        executor = TacticExecutor(mock_adapter)

        await executor.execute(vector, mock_pipeline, _render_fn)

        # Only the 3rd prompt has success_indicators
        assert mock_pipeline.evaluate.call_count == 1

    @pytest.mark.asyncio
    async def test_success_on_final_turn(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """If the final turn succeeds detection, return successful result."""
        mock_pipeline.evaluate.return_value = _make_verdict(successful=True)
        vector = _make_vector()
        executor = TacticExecutor(mock_adapter)

        result = await executor.execute(vector, mock_pipeline, _render_fn)

        assert result.successful is True
        assert result.evidence["tactic"] == "crescendo"
        assert result.evidence["turn"] == 3
        assert result.evidence["total_turns"] == 3

    @pytest.mark.asyncio
    async def test_failure_when_no_success(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """All turns fail detection → unsuccessful result."""
        vector = _make_vector()
        executor = TacticExecutor(mock_adapter)

        result = await executor.execute(vector, mock_pipeline, _render_fn)

        assert result.successful is False
        assert result.evidence["tactic"] == "crescendo"
        assert result.evidence["turns_attempted"] == 3

    @pytest.mark.asyncio
    async def test_empty_prompts(self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock) -> None:
        vector = _make_vector(prompts=[])
        executor = TacticExecutor(mock_adapter)

        result = await executor.execute(vector, mock_pipeline, _render_fn)

        assert result.successful is False
        assert result.error == "No prompts defined for this attack vector"

    @pytest.mark.asyncio
    async def test_token_accumulation(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """Tokens should be accumulated across all turns."""
        vector = _make_vector()
        executor = TacticExecutor(mock_adapter)

        result = await executor.execute(vector, mock_pipeline, _render_fn)

        # Each response has 30 total tokens, 3 turns
        assert result.token_usage.total_tokens == 90

    @pytest.mark.asyncio
    async def test_timeout_continues_sequence(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """A timeout on one turn should not stop the sequence."""
        mock_adapter.invoke.side_effect = [
            _make_response(),
            TimeoutError("timeout"),
            _make_response(),
        ]
        # Make the 3rd prompt also have indicators so detection can run
        prompts = [
            AttackPrompt(template="p1", success_indicators=[]),
            AttackPrompt(template="p2", success_indicators=[]),
            AttackPrompt(template="p3", success_indicators=["x"]),
        ]
        vector = _make_vector(prompts=prompts)
        executor = TacticExecutor(mock_adapter)

        await executor.execute(vector, mock_pipeline, _render_fn)

        # Should have tried all 3
        assert mock_adapter.invoke.call_count == 3

    @pytest.mark.asyncio
    async def test_early_success_stops(
        self, mock_adapter: AsyncMock, mock_pipeline: AsyncMock
    ) -> None:
        """If a mid-sequence prompt succeeds, stop early."""
        prompts = [
            AttackPrompt(template="setup"),
            AttackPrompt(template="exploit", success_indicators=["hit"]),
            AttackPrompt(template="never reached", success_indicators=["x"]),
        ]
        mock_pipeline.evaluate.return_value = _make_verdict(successful=True)
        vector = _make_vector(prompts=prompts)
        executor = TacticExecutor(mock_adapter)

        result = await executor.execute(vector, mock_pipeline, _render_fn)

        assert result.successful is True
        assert result.evidence["turn"] == 2
        # Only 2 invocations — the 3rd was never reached
        assert mock_adapter.invoke.call_count == 2


# ── YAML vectors validation ──────────────────────────────────────────


class TestMultiTurnVectorsYAML:
    def test_vectors_load(self, shared_attack_library: AttackLibrary) -> None:
        """Multi-turn tactic vectors should load without errors."""
        library = shared_attack_library
        all_vectors = library.vectors

        multi_turn = [v for v in all_vectors if v.tactic != "single"]
        assert len(multi_turn) >= 10

    def test_vectors_have_multi_turn_tag(self, shared_attack_library: AttackLibrary) -> None:
        library = shared_attack_library
        all_vectors = library.vectors

        multi_turn = [v for v in all_vectors if v.tactic != "single"]
        for v in multi_turn:
            assert "multi_turn" in v.tags, f"Vector {v.id} missing 'multi_turn' tag"

    def test_vectors_have_multiple_prompts(self, shared_attack_library: AttackLibrary) -> None:
        library = shared_attack_library
        all_vectors = library.vectors

        multi_turn = [v for v in all_vectors if v.tactic != "single"]
        for v in multi_turn:
            assert len(v.prompts) >= 2, f"Vector {v.id} has only {len(v.prompts)} prompt(s)"

    def test_vectors_have_success_indicators_on_later_prompts(
        self, shared_attack_library: AttackLibrary
    ) -> None:
        library = shared_attack_library
        all_vectors = library.vectors

        multi_turn = [v for v in all_vectors if v.tactic != "single"]
        for v in multi_turn:
            has_indicators = any(p.success_indicators for p in v.prompts)
            assert has_indicators, f"Vector {v.id} has no success_indicators on any prompt"
