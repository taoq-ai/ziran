"""Integration test: the detection-accuracy harness over the seed dataset (spec 021).

Runs the real DetectorPipeline (with replayed judge verdicts) end-to-end and
asserts the run is deterministic — guarding SC-006.
"""

from __future__ import annotations

import pytest

from benchmarks.detection_accuracy import DATASET_DIR, run_benchmark
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
    """The hand-labelled seed is internally consistent — pipeline matches labels."""
    result = run_benchmark(DATASET_DIR)
    # Seed is constructed so the pipeline agrees with every overall label.
    assert result.pipeline.confusion.fp == 0
    assert result.pipeline.confusion.fn == 0
