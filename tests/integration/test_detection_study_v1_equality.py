"""Integration: with no task or payload the patched pipeline equals study-v1 (spec 063).

``tests/fixtures/detection/study_v1_verdicts.json`` holds the verdict of ziran
``study-v1`` (32281c77) on every item of ``benchmarks/ground_truth/detection``
as it stood at that tag; ``specs/063-provenance-side-effect/plan.md`` gives the
command that wrote it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.detection_accuracy import DATASET_DIR, load_examples
from benchmarks.replay_llm_client import ReplayLLMClient
from ziran.application.detectors.ensemble import EnsembleConfig
from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.interfaces.adapter import AgentResponse

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parents[1] / "fixtures" / "detection" / "study_v1_verdicts.json"


async def _verdicts(*, with_metadata: bool) -> dict[str, dict[str, Any]]:
    examples = load_examples(DATASET_DIR)
    t = DetectorThresholds().model_copy(update={"ensemble": EnsembleConfig()})
    pipeline = DetectorPipeline(
        llm_client=ReplayLLMClient(examples), detector_config=DetectorConfig(thresholds=t)
    )
    out: dict[str, dict[str, Any]] = {}
    for ex in examples:
        spec = AttackPrompt(
            template=ex.attack.vector_id,
            success_indicators=ex.prompt_success_indicators,
            failure_indicators=ex.prompt_failure_indicators,
        )
        response = AgentResponse(
            content=ex.response_text,
            tool_calls=[tc.model_dump(exclude_none=True) for tc in ex.tool_calls],
            metadata=ex.metadata if with_metadata else {},
        )
        v = await pipeline.evaluate(ex.attack.vector_id, response, spec)
        out[ex.example_id] = {
            "successful": v.successful,
            "score": v.score,
            "reasoning": v.reasoning,
            "detectors": [[r.detector_name, r.score, r.confidence] for r in v.detector_results],
            "label": ex.label,
            "has_task": "trusted_task" in ex.metadata,
        }
    return out


async def test_every_study_v1_item_scores_as_study_v1() -> None:
    v1 = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = await _verdicts(with_metadata=True)
    assert len(v1) == 222
    assert v1.keys() <= now.keys()
    for example_id, expected in v1.items():
        got = {k: now[example_id][k] for k in expected}
        assert got == expected, example_id


async def test_benign_task_items_need_the_task() -> None:
    v1 = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with_task = await _verdicts(with_metadata=True)
    without = await _verdicts(with_metadata=False)
    new = [k for k, v in with_task.items() if v["has_task"]]
    assert new, "the dataset holds benign-task items with a trusted task"
    assert not set(new) & v1.keys()
    for k in new:
        assert with_task[k]["label"] == "no_compromise"
        assert not with_task[k]["successful"], k
        assert without[k]["successful"], k  # study-v1 flags them: CI now sees this failure
