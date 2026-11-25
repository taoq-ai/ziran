"""Integration test: the detection-accuracy harness over the seed dataset (spec 021).

Runs the real DetectorPipeline (with replayed judge verdicts) end-to-end and
asserts the run is deterministic — guarding SC-006.
"""

from __future__ import annotations

import pytest

from benchmarks.detection_accuracy import DATASET_DIR, ORIGINAL_CATEGORIES, run_benchmark
from ziran.application.detectors.thresholds import DetectorThresholds

pytestmark = pytest.mark.integration


def test_harness_runs_real_pipeline_over_seed() -> None:
    result = run_benchmark(DATASET_DIR)
    assert result.dataset_size > 0
    # All four in-scope detectors are reported.
    assert set(result.detectors) == {"refusal", "indicator", "side_effect", "llm_judge"}
    # Each reported detector has its applicable count and a confusion matrix.
    for metrics in result.detectors.values():
        assert metrics.confusion.total == metrics.applicable
    assert 0.0 <= result.pipeline.f1 <= 1.0


def test_harness_is_deterministic() -> None:
    """SC-006: same dataset + thresholds → identical metrics across runs."""
    t = DetectorThresholds()
    first = run_benchmark(DATASET_DIR, t)
    second = run_benchmark(DATASET_DIR, t)
    assert first.pipeline.model_dump() == second.pipeline.model_dump()
    assert {k: v.f1 for k, v in first.detectors.items()} == {
        k: v.f1 for k, v in second.detectors.items()
    }


def test_seed_pipeline_classifies_correctly() -> None:
    """The hand-labelled seed is internally consistent: no false success, and every
    judged compromise is found.

    Only the spec-021 categories: the spec-078 slices exist to show detector errors.
    The 52 full_compliance items hold no attack prompt, so the benchmark can pass no
    payload: under study-v2.1 change 7 they are listed for review, not counted.
    """
    result = run_benchmark(DATASET_DIR, categories=ORIGINAL_CATEGORIES)
    assert result.pipeline.confusion.fp == 0
    assert result.pipeline.confusion.fn == 52
    judged = result.per_category_confusion["partial_compliance"]["pipeline"]
    assert (judged.tp, judged.fn) == (26, 0)


def test_harness_ignores_ensemble_block() -> None:
    """Spec 041: the benchmark always scores the single replayed judge."""
    from ziran.application.detectors.ensemble import EnsembleConfig, JudgeMemberConfig

    ensemble = EnsembleConfig(
        enabled=True,
        judges=(JudgeMemberConfig(name="primary"), JudgeMemberConfig(name="second", model="m2")),
    )
    result = run_benchmark(DATASET_DIR, DetectorThresholds(ensemble=ensemble))
    assert result.pipeline.model_dump() == run_benchmark(DATASET_DIR).pipeline.model_dump()
