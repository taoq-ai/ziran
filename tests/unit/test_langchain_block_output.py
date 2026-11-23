"""LangChain agent output given as a list of content blocks (spec 090)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

BLOCKS: list[Any] = [
    {"type": "text", "text": "hi"},
    {"type": "tool_use", "id": "t1", "name": "search", "input": {"q": "x"}},
]


def _agent(output: Any) -> MagicMock:
    agent = MagicMock()
    agent.ainvoke = AsyncMock(return_value={"output": output, "intermediate_steps": []})
    agent.memory = None
    return agent


@pytest.mark.unit
class TestBlockOutput:
    async def test_text_blocks_are_joined_and_others_ignored(self) -> None:
        resp = await LangChainAdapter(_agent(BLOCKS)).invoke("hello")
        assert resp.content == "hi"

    async def test_block_objects_and_bare_strings(self) -> None:
        output = [SimpleNamespace(type="text", text="a"), "b", {"type": "image"}, {"text": 3}]
        resp = await LangChainAdapter(_agent(output)).invoke("hello")
        assert resp.content == "ab"

    async def test_empty_list_gives_empty_content(self) -> None:
        resp = await LangChainAdapter(_agent([])).invoke("hello")
        assert resp.content == ""

    async def test_iteration_limit_in_a_text_block_is_still_detected(self) -> None:
        output = [{"type": "text", "text": "Agent stopped due to iteration limit."}]
        resp = await LangChainAdapter(_agent(output)).invoke("hello")
        assert resp.metadata["hit_iteration_limit"] is True

    async def test_string_output_is_unchanged(self) -> None:
        adapter = LangChainAdapter(_agent("  plain reply "))
        resp = await adapter.invoke("hello")
        assert resp.content == "  plain reply "
        assert adapter.get_state().conversation_history[-1]["content"] == "  plain reply "

    async def test_attack_executor_scores_the_vector(self) -> None:
        from ziran.application.agent_scanner.attack_executor import AttackExecutor
        from ziran.domain.entities.attack import AttackPrompt, AttackVector
        from ziran.domain.entities.detection import DetectionVerdict

        vector = AttackVector(
            id="v_blocks",
            name="Blocks",
            category="prompt_injection",
            target_phase="reconnaissance",
            description="test vector",
            severity="high",
            prompts=[AttackPrompt(template="prompt", success_indicators=["leak"])],
        )
        pipeline = MagicMock()
        pipeline.evaluate = AsyncMock(return_value=DetectionVerdict(successful=False, score=0.0))

        result = await AttackExecutor(LangChainAdapter(_agent(BLOCKS)), pipeline).execute(vector)

        pipeline.evaluate.assert_awaited_once()
        assert result.agent_response == "hi"
        assert "prompt_errors" not in result.evidence
        assert "outcome" not in result.evidence
