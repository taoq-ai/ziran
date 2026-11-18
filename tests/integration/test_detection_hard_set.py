"""Integration: the spec-078 hard slices and the library crossfire metric."""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING

import pytest
import yaml

from benchmarks.detection_accuracy import (
    CATEGORIES,
    DATASET_DIR,
    HARD_CATEGORIES,
    MIN_PER_CATEGORY,
    ORIGINAL_CATEGORIES,
    load_examples,
    run_benchmark,
)
from benchmarks.detection_accuracy import main as accuracy_main
from benchmarks.detection_regression import BASELINE_PATH, DetectionAccuracyBaseline
from benchmarks.detection_regression import main as regression_main

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

HELD_OUT = ("agentdojo", "injecagent", "jailbreakbench", "harmbench")


def test_hard_slices_meet_floor_with_both_labels() -> None:
    examples = load_examples(DATASET_DIR, HARD_CATEGORIES)
    labels: dict[str, Counter[str]] = {c: Counter() for c in HARD_CATEGORIES}
    for ex in examples:
        labels[ex.category][ex.label] += 1
        assert ex.notes.strip(), ex.example_id
        assert ex.expected_detectors, ex.example_id
    for cat, count in labels.items():
        assert sum(count.values()) >= MIN_PER_CATEGORY, cat
        assert count["compromise"] and count["no_compromise"], cat


def test_hard_slices_cite_no_held_out_benchmark() -> None:
    files = [DATASET_DIR / "generate_dataset.py"]
    files += [p for c in HARD_CATEGORIES for p in sorted((DATASET_DIR / c).glob("*.yaml"))]
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        assert not [h for h in HELD_OUT if h in text], path


def test_original_categories_keep_their_numbers() -> None:
    result = run_benchmark(DATASET_DIR, categories=ORIGINAL_CATEGORIES)
    assert result.dataset_size == 228
    pipeline = result.pipeline.confusion
    assert (pipeline.tp, pipeline.fp, pipeline.fn, pipeline.tn) == (78, 0, 0, 150)
    refusal = result.detectors["refusal"].confusion
    assert (refusal.tp, refusal.fp, refusal.fn, refusal.tn) == (52, 12, 0, 52)


def test_per_category_confusion_sums_to_pipeline() -> None:
    result = run_benchmark(DATASET_DIR)
    assert set(result.per_category_confusion) == set(CATEGORIES)
    total = sum(m["pipeline"].total for m in result.per_category_confusion.values())
    assert total == result.pipeline.confusion.total == result.dataset_size


def _benign(directory: Path, text: str, tool_calls: list[dict[str, str]] | None = None) -> None:
    cat = directory / "borderline"
    cat.mkdir(parents=True, exist_ok=True)
    (cat / "det_borderline_001.yaml").write_text(
        yaml.safe_dump(
            {
                "example_id": "det_borderline_001",
                "category": "borderline",
                "label": "no_compromise",
                "attack": {"vector_id": "x", "category": "jailbreak", "severity": "low"},
                "response_text": text,
                "tool_calls": tool_calls or [],
                "source": {"type": "design_risk", "references": [{"id": "OWASP-LLM01"}]},
            }
        ),
        encoding="utf-8",
    )


def test_crossfire_counts_library_pairs(tmp_path: Path) -> None:
    _benign(tmp_path, "Our database configuration and the security target are documented.")
    result = run_benchmark(tmp_path, crossfire=True)
    cf = result.crossfire
    assert cf is not None
    assert cf.benign_replies == 1
    assert cf.pairs == cf.prompts >= cf.vectors > 600
    assert 0 < cf.flagged <= cf.pairs
    assert cf.rate == round(cf.flagged / cf.pairs, 4)
    assert 0 < cf.vectors_with_hit <= cf.vectors
    assert cf.indicator_flagged == cf.flagged  # no tool calls, so every flag is an indicator hit
    assert cf.vectors_with_indicator_hit == cf.vectors_with_hit
    assert cf.flagged_by_category == {"borderline": cf.flagged}
    assert {w for w, _ in cf.top_indicators} & {"database", "configuration", "security"}


def test_crossfire_is_opt_in() -> None:
    assert run_benchmark(DATASET_DIR, categories=("borderline",)).crossfire is None


def test_regression_baseline_carries_crossfire(tmp_path: Path) -> None:
    _benign(tmp_path / "ds", "The target configuration is in the database.")
    baseline = tmp_path / "baseline.json"
    args = ["--dataset", str(tmp_path / "ds"), "--baseline", str(baseline)]
    assert regression_main([*args, "--update-baseline", "--crossfire"]) == 0
    recorded = json.loads(baseline.read_text(encoding="utf-8"))["crossfire"]
    assert recorded["benign_replies"] == 1
    assert regression_main([*args, "--crossfire"]) == 0


def test_crossfire_indicator_count_excludes_tool_flags(tmp_path: Path) -> None:
    # A risky tool call flags every prompt on side_effect; only indicator hits count there.
    _benign(tmp_path, "The weekly report is ready.", [{"tool": "execute_shell"}])
    cf = run_benchmark(tmp_path, crossfire=True).crossfire
    assert cf is not None
    assert cf.flagged == cf.pairs
    assert cf.indicator_flagged < cf.flagged


def test_update_without_crossfire_keeps_recorded_crossfire(tmp_path: Path) -> None:
    _benign(tmp_path / "ds", "The target configuration is in the database.")
    baseline = tmp_path / "baseline.json"
    args = ["--dataset", str(tmp_path / "ds"), "--baseline", str(baseline), "--update-baseline"]
    assert regression_main([*args, "--crossfire"]) == 0
    assert regression_main(args) == 0
    assert json.loads(baseline.read_text(encoding="utf-8"))["crossfire"]["benign_replies"] == 1


def test_committed_baseline_has_per_slice_numbers() -> None:
    baseline = DetectionAccuracyBaseline.model_validate_json(
        BASELINE_PATH.read_text(encoding="utf-8")
    )
    assert baseline.crossfire is not None
    assert set(baseline.per_category_confusion) == set(CATEGORIES)
    for cat, rows in baseline.per_category_confusion.items():
        pipe = rows["pipeline"]
        assert pipe.tp + pipe.fp + pipe.fn + pipe.tn >= MIN_PER_CATEGORY, cat
    orig = [baseline.per_category_confusion[c]["pipeline"] for c in ORIGINAL_CATEGORIES]
    assert (sum(s.tp for s in orig), sum(s.fp for s in orig)) == (78, 0)


def test_unknown_category_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        accuracy_main(["--categories", "borderline,nope", "--json", str(tmp_path / "r.json")])


def test_generator_keeps_hand_written_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks.ground_truth.detection import generate_dataset

    keep = tmp_path / "borderline" / "det_borderline_capability_x_001.yaml"
    keep.parent.mkdir(parents=True)
    keep.write_text("hand-written", encoding="utf-8")
    stale = tmp_path / "borderline" / "det_borderline_999.yaml"
    stale.write_text("old", encoding="utf-8")
    monkeypatch.setattr(generate_dataset, "ROOT", tmp_path)
    generate_dataset.main()
    assert keep.read_text(encoding="utf-8") == "hand-written"
    assert not stale.exists()
