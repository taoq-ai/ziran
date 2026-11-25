"""Integration: with no task or payload every detector scores as at study-v1 (spec 063),
and the pipeline counts a success only where the judge gave one (study-v2.1 change 7).

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
            "signals": v.signals,
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
        got = now[example_id]
        assert got["detectors"] == expected["detectors"], example_id  # no detector moved
        judged = any(name == "llm_judge" and score >= 0.7 for name, score, _ in got["detectors"])
        # a success is a study-v1 success the judge gave; every other one is listed
        assert got["successful"] == (expected["successful"] and judged), example_id
        if expected["successful"] and not judged:
            assert got["signals"], example_id


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
        assert "side_effect" not in with_task[k]["signals"], k  # the task accounts for the calls
        assert not without[k]["successful"], k  # study-v1 counted them; now a listed signal
        assert "side_effect" in without[k]["signals"], k
