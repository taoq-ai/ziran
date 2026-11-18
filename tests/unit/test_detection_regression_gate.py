"""Unit tests for the detection-accuracy gate rules and PR comment (spec 077)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from benchmarks import detection_regression
from benchmarks.detection_accuracy import (
    ConfusionMatrix,
    DetectorAccuracyResult,
    DetectorMetrics,
    _metrics,
)
from benchmarks.detection_regression import (
    BASELINE_PATH,
    COMMENT_MARKER,
    PIPELINE,
    DetectionAccuracyBaseline,
    gate_failures,
    render_comment,
    result_snapshots,
)

pytestmark = pytest.mark.unit

# Today's 228-example baseline: pipeline 78/0/0/150, refusal 52/12/0/52.
BASE_PIPELINE = (78, 0, 0, 150)
BASE_REFUSAL = (52, 12, 0, 52)


Counts = tuple[int, int, int, int]


def _m(c: Counts) -> DetectorMetrics:
    cm = ConfusionMatrix(tp=c[0], fp=c[1], fn=c[2], tn=c[3])
    return _metrics(cm, cm.total)


def _result(pipeline: Counts, refusal: Counts = BASE_REFUSAL) -> DetectorAccuracyResult:
    return DetectorAccuracyResult(
        timestamp="t",
        dataset_size=sum(pipeline),
        per_category_counts={},
        per_detector_applicable={},
        detectors={"refusal": _m(refusal)},
        pipeline=_m(pipeline),
    )


def _baseline() -> DetectionAccuracyBaseline:
    return DetectionAccuracyBaseline.from_result(_result(BASE_PIPELINE))


def test_one_lost_detection_fails_on_recall() -> None:
    head = _result((77, 0, 1, 150))
    assert head.pipeline.recall == 0.9872
    # Inside today's F1 tolerance, so only the recall rule catches it.
    assert 1.0 - head.pipeline.f1 < 0.02
    failures = gate_failures(_baseline(), head)
    assert len(failures) == 1
    assert "pipeline recall" in failures[0]


def test_one_added_false_positive_fails_on_fpr() -> None:
    failures = gate_failures(_baseline(), _result((78, 1, 0, 149)))
    assert len(failures) == 1
    assert "pipeline FPR" in failures[0]


def test_unchanged_result_passes() -> None:
    assert gate_failures(_baseline(), _result(BASE_PIPELINE)) == []


def test_old_baseline_without_new_keys_gates_on_f1_only() -> None:
    old = DetectionAccuracyBaseline.model_validate_json(
        '{"timestamp": "t", "pipeline_f1": 1.0, "tolerance": 0.02,'
        ' "per_detector_f1": {"refusal": 0.8966}, "dataset_size": 228}'
    )
    assert old.pipeline is None
    assert old.snapshots() == {}
    assert gate_failures(old, _result((77, 0, 1, 150))) == []
    failures = gate_failures(old, _result((70, 0, 8, 150)))
    assert len(failures) == 1
    assert "pipeline F1" in failures[0]


def test_baseline_records_new_fields() -> None:
    b = _baseline()
    assert b.pipeline is not None
    assert b.pipeline.fpr == 0.0
    assert b.per_detector["refusal"].fpr == 0.1875
    assert b.per_detector["refusal"].precision == 0.8125
    assert b.per_detector_f1 == {"refusal": 0.8966}


def test_comment_shows_head_base_and_deltas() -> None:
    head = result_snapshots(_result((77, 0, 1, 150), refusal=(52, 13, 0, 51)))
    base = result_snapshots(_result(BASE_PIPELINE))
    text = render_comment(
        head,
        base,
        ["pipeline recall 0.9872 is below"],
        base_note="note",
        head_size=228,
        base_size=228,
    )
    assert text.startswith(COMMENT_MARKER)
    assert "**Gate: FAIL**" in text
    assert "| refusal | 52/13/0/51 (base 52/12/0/52) |" in text
    assert "0.1875" in text  # base FPR of refusal
    assert "(base 1.0, -0.0128)" in text  # pipeline recall delta
    assert f"| **{PIPELINE}** |" in text
    assert "note" in text


def test_comment_marks_unchanged_and_missing_base() -> None:
    head = result_snapshots(_result(BASE_PIPELINE))
    text = render_comment(head, {}, [], base_note="", head_size=228, base_size=None)
    assert "**Gate: pass**" in text
    assert "(base n/a)" in text
    same = render_comment(head, head, [], base_note="", head_size=228, base_size=228)
    assert "| refusal | 52/12/0/52 (=) | 0.8125 (=) |" in same


def test_unreadable_base_result_falls_back_to_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        detection_regression, "run_benchmark", lambda _d, **_kw: _result(BASE_PIPELINE)
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(_baseline().model_dump_json(), encoding="utf-8")
    bad = tmp_path / "base.json"
    bad.write_text("not json", encoding="utf-8")
    comment = tmp_path / "comment.md"
    argv = ["--baseline", str(baseline), "--base-result", str(bad), "--comment", str(comment)]
    assert detection_regression.main(argv) == 0
    text = comment.read_text(encoding="utf-8")
    assert "baseline file in this PR" in text
    assert "(=)" in text


def test_base_result_feeds_comment_and_gate_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        detection_regression, "run_benchmark", lambda _d, **_kw: _result((77, 0, 1, 150))
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(_baseline().model_dump_json(), encoding="utf-8")
    base = tmp_path / "base.json"
    base.write_text(_result(BASE_PIPELINE).model_dump_json(), encoding="utf-8")
    comment = tmp_path / "comment.md"
    argv = ["--baseline", str(baseline), "--base-result", str(base), "--comment", str(comment)]
    assert detection_regression.main(argv) == 1
    text = comment.read_text(encoding="utf-8")
    assert "PR base code" in text
    assert "pipeline recall" in text


def test_committed_baseline_records_recall_and_fpr() -> None:
    """An old-format committed baseline would silently turn the recall and FPR rules off."""
    b = DetectionAccuracyBaseline.model_validate_json(BASELINE_PATH.read_text(encoding="utf-8"))
    assert b.pipeline is not None
    assert b.per_detector


def test_comment_shows_dataset_sizes_and_warns_when_they_differ() -> None:
    head = result_snapshots(_result(BASE_PIPELINE))
    same = render_comment(head, head, [], base_note="", head_size=228, base_size=228)
    assert "Examples scored: head 228, base 228." in same
    assert ":warning:" not in same
    diff = render_comment(head, head, [], base_note="", head_size=447, base_size=228)
    assert "Examples scored: head 447, base 228." in diff
    assert ":warning:" in diff


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")
def test_comment_selector_edits_only_the_bot_marker_comment() -> None:
    """The workflow's jq filter must skip a user's comment that copies the marker."""
    workflow = Path(__file__).parents[2] / ".github" / "workflows" / "detection-accuracy.yml"
    steps = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"][
        "detection-accuracy-comment"
    ]["steps"]
    script = next(s["run"] for s in steps if "run" in s)
    match = re.search(r"--jq '([^']+)'", script)
    assert match is not None
    comments = [
        {"id": 111, "user": {"login": "someone"}, "body": f"{COMMENT_MARKER} forged"},
        {"id": 222, "user": {"login": "github-actions[bot]"}, "body": "Benchmark report"},
        {"id": 333, "user": {"login": "github-actions[bot]"}, "body": f"{COMMENT_MARKER}\nreal"},
    ]
    out = subprocess.run(
        ["jq", match.group(1)],
        input=json.dumps(comments),
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert out.stdout.split() == ["333"]
