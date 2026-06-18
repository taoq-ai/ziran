"""Integration tests for many-shot execution (spec 023, T011/T014/T016)."""

from __future__ import annotations

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.pipeline import DetectorPipeline

pytestmark = pytest.mark.integration


def _a_many_shot_vector() -> object:
    return next(v for v in AttackLibrary().vectors if v.many_shot is not None)


async def test_prompt_stacks_shots_before_final_request() -> None:
    """FR-002/FR-008: the sent prompt = N shots + the final request, evaluated normally."""
    vector = _a_many_shot_vector()
    adapter = MockAgentAdapter(responses=["I can't help with that."])
    result = await AttackExecutor(adapter, DetectorPipeline()).execute(vector)

    assert adapter.invocations, "adapter should have been invoked"
    sent = adapter.invocations[0]
    assert sent.count("Q: ") == vector.many_shot.n_shots  # stacked shots
    assert vector.prompts[0].variables["final_request"] in sent  # final request appended last
    assert result.vector_id == vector.id  # produced via the normal path


async def test_scan_time_override_changes_shot_count() -> None:
    """T014: a scan-time n_shots override changes the number of stacked shots."""
    vector = _a_many_shot_vector()
    adapter = MockAgentAdapter(responses=["nope"])
    await AttackExecutor(adapter, DetectorPipeline(), n_shots=7).execute(vector)
    assert adapter.invocations[0].count("Q: ") == 7


async def test_over_capacity_target_is_skipped_and_warned() -> None:
    """SC-004/FR-007: a tiny context budget skips the vector without sending the prompt."""
    vector = _a_many_shot_vector()
    adapter = MockAgentAdapter(responses=["should not be called"])
    result = await AttackExecutor(adapter, DetectorPipeline(), context_window=100).execute(vector)

    assert not adapter.invocations, "over-capacity prompt must NOT be sent"
    assert result.successful is False
    assert "skipped" in result.evidence
