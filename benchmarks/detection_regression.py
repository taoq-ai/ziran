"""Detection-accuracy regression gate (spec 021, US3; spec 077).

Compares the current pipeline against a recorded baseline and fails when F1
drops more than a fixed absolute tolerance (default 0.02), when recall falls
below the baseline, or when the false positive rate rises above it (spec 077,
no tolerance). Per-detector numbers are reported but never cause failure.

Usage:
    uv run python benchmarks/detection_regression.py
    uv run python benchmarks/detection_regression.py --update-baseline
    uv run python benchmarks/detection_regression.py --format markdown
    uv run python benchmarks/detection_regression.py --comment c.md --base-result base.json

Exit codes:
    0  pass (no gate rule broken, or baseline updated)
    1  regression (F1 beyond tolerance, recall drop or FPR rise)
    2  baseline missing (run with --update-baseline to create it)
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from benchmarks.detection_accuracy import (
    DATASET_DIR,
    ConfusionMatrix,
    DetectorAccuracyResult,
    DetectorMetrics,
    run_benchmark,
)

BASELINE_PATH = Path(__file__).parent / "results" / "detection_accuracy_baseline.json"
DEFAULT_TOLERANCE = 0.02
PIPELINE = "pipeline"
COMMENT_MARKER = "<!-- ziran-detection-accuracy -->"


class MetricSnapshot(BaseModel):
    """The numbers one detector (or the pipeline) is compared on."""

    precision: float
    recall: float
    f1: float
    fpr: float
    confusion: ConfusionMatrix

    @classmethod
    def of(cls, m: DetectorMetrics) -> MetricSnapshot:
        cm = m.confusion
        fpr = round(cm.fp / (cm.fp + cm.tn), 4) if (cm.fp + cm.tn) else 0.0
        return cls(precision=m.precision, recall=m.recall, f1=m.f1, fpr=fpr, confusion=cm)


def result_snapshots(result: DetectorAccuracyResult) -> dict[str, MetricSnapshot]:
    """Per-detector snapshots plus the pipeline under ``PIPELINE``."""
    out = {name: MetricSnapshot.of(m) for name, m in result.detectors.items()}
    out[PIPELINE] = MetricSnapshot.of(result.pipeline)
    return out


class DetectionAccuracyBaseline(BaseModel):
    """Recorded reference the regression gate compares against."""

    timestamp: str
    pipeline_f1: float
    tolerance: float = DEFAULT_TOLERANCE
    per_detector_f1: dict[str, float]
    dataset_size: int
    # Spec 077: absent in older baselines, which then gate on F1 alone.
    pipeline: MetricSnapshot | None = None
    per_detector: dict[str, MetricSnapshot] = {}

    @classmethod
    def from_result(
        cls, result: DetectorAccuracyResult, *, tolerance: float = DEFAULT_TOLERANCE
    ) -> DetectionAccuracyBaseline:
        return cls(
            timestamp=datetime.now(tz=UTC).isoformat(),
            pipeline_f1=result.pipeline.f1,
            tolerance=tolerance,
            per_detector_f1={name: m.f1 for name, m in result.detectors.items()},
            dataset_size=result.dataset_size,
            pipeline=MetricSnapshot.of(result.pipeline),
            per_detector={name: MetricSnapshot.of(m) for name, m in result.detectors.items()},
        )

    def snapshots(self) -> dict[str, MetricSnapshot]:
        """Same shape as ``result_snapshots``; empty for an old baseline."""
        if self.pipeline is None:
            return {}
        return {**self.per_detector, PIPELINE: self.pipeline}


def gate_failures(baseline: DetectionAccuracyBaseline, result: DetectorAccuracyResult) -> list[str]:
    """Return one line per broken gate rule; an empty list means pass."""
    failures: list[str] = []
    f1 = result.pipeline.f1
    if (baseline.pipeline_f1 - f1) > baseline.tolerance:
        failures.append(
            f"pipeline F1 {f1} dropped more than {baseline.tolerance} "
            f"below baseline {baseline.pipeline_f1}"
        )
    if baseline.pipeline is not None:
        head = MetricSnapshot.of(result.pipeline)
        if head.recall < baseline.pipeline.recall:
            failures.append(
                f"pipeline recall {head.recall} is below baseline {baseline.pipeline.recall}"
            )
        if head.fpr > baseline.pipeline.fpr:
            failures.append(f"pipeline FPR {head.fpr} is above baseline {baseline.pipeline.fpr}")
    return failures


def _cell(head: str, base: str | None, delta: float | None = None) -> str:
    if base is None:
        return f"{head} (base n/a)"
    if head == base:
        return f"{head} (=)"
    return f"{head} (base {base}, {delta:+})" if delta is not None else f"{head} (base {base})"


def _counts(cm: ConfusionMatrix) -> str:
    return f"{cm.tp}/{cm.fp}/{cm.fn}/{cm.tn}"


def render_comment(
    head: dict[str, MetricSnapshot],
    base: dict[str, MetricSnapshot],
    failures: list[str],
    *,
    base_note: str,
    head_size: int,
    base_size: int | None,
) -> str:
    """Markdown PR comment: head vs base per detector and for the pipeline."""
    lines = [COMMENT_MARKER, "### Detection accuracy: head vs base", ""]
    lines.append("**Gate: FAIL**" if failures else "**Gate: pass**")
    lines += [f"- {f}" for f in failures]
    lines += [
        "",
        "| detector | TP/FP/FN/TN | precision | recall | F1 | FPR |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name in [*head, *(n for n in base if n not in head)]:
        h, b = head.get(name), base.get(name)
        label = f"**{name}**" if name == PIPELINE else name
        if h is None:
            lines.append(f"| {label} | n/a | n/a | n/a | n/a | n/a |")
            continue
        cells = [_cell(_counts(h.confusion), _counts(b.confusion) if b else None)]
        for key in ("precision", "recall", "f1", "fpr"):
            hv = getattr(h, key)
            bv = getattr(b, key) if b else None
            delta = round(hv - bv, 4) if bv is not None else None
            cells.append(_cell(str(hv), str(bv) if bv is not None else None, delta))
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Each cell is the PR head; `(=)` means the base is the same.",
        base_note,
        f"Examples scored: head {head_size}, base {base_size if base_size is not None else 'n/a'}.",
    ]
    if base_size is not None and base_size != head_size:
        lines.append(
            ":warning: Head and base scored different example counts, so the deltas mix "
            "dataset and detector changes."
        )
    lines.append(
        "Gate (against `benchmarks/results/detection_accuracy_baseline.json`): fails on any "
        "pipeline recall drop, any pipeline FPR rise, or a pipeline F1 drop over the tolerance."
    )
    return "\n".join(lines) + "\n"


def _render(
    baseline: DetectionAccuracyBaseline,
    result: DetectorAccuracyResult,
    *,
    failures: list[str],
    fmt: str,
) -> str:
    delta = round(result.pipeline.f1 - baseline.pipeline_f1, 4)
    status = "REGRESSION" if failures else "OK"
    lines = [
        f"Detection-accuracy gate: {status}",
        *(f"  FAIL: {f}" for f in failures),
        f"  pipeline F1: {result.pipeline.f1} (baseline {baseline.pipeline_f1}, "
        f"delta {delta:+}, tolerance -{baseline.tolerance})",
    ]
    for name, m in result.detectors.items():
        base = baseline.per_detector_f1.get(name)
        d = f"{round(m.f1 - base, 4):+}" if base is not None else "n/a"
        lines.append(f"  {name} F1: {m.f1} (baseline {base}, delta {d}) [non-blocking]")
    if fmt == "markdown":
        return "```\n" + "\n".join(lines) + "\n```"
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZIRAN detection-accuracy regression gate")
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--format", choices=("table", "markdown"), default="table")
    parser.add_argument("--comment", type=Path, help="Write a head vs base PR comment to PATH")
    parser.add_argument(
        "--base-result",
        type=Path,
        help="DetectorAccuracyResult JSON of the PR base (default: the baseline file)",
    )
    args = parser.parse_args(argv)

    result = run_benchmark(args.dataset)

    if args.update_baseline:
        baseline = DetectionAccuracyBaseline.from_result(result)
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
        print(f"Updated baseline at {args.baseline} (pipeline F1 {baseline.pipeline_f1})")
        return 0

    if not args.baseline.exists():
        print(
            f"No baseline at {args.baseline}. Create it with --update-baseline.",
        )
        return 2

    baseline = DetectionAccuracyBaseline.model_validate_json(
        args.baseline.read_text(encoding="utf-8")
    )
    failures = gate_failures(baseline, result)
    print(_render(baseline, result, failures=failures, fmt=args.format))
    if args.comment:
        _write_comment(args.comment, args.base_result, baseline, result, failures)
    return 1 if failures else 0


def _write_comment(
    path: Path,
    base_result: Path | None,
    baseline: DetectionAccuracyBaseline,
    result: DetectorAccuracyResult,
    failures: list[str],
) -> None:
    base, note = baseline.snapshots(), ""
    base_size: int | None = baseline.dataset_size
    if base_result is not None:
        try:
            raw = base_result.read_text(encoding="utf-8")
            base_run = DetectorAccuracyResult.model_validate_json(raw)
            base, base_size = result_snapshots(base_run), base_run.dataset_size
            note = "_Base: the PR base code scored on this PR's dataset._"
        # ValueError covers ValidationError and UnicodeDecodeError.
        except (OSError, ValueError) as exc:
            print(f"warning: cannot read --base-result {base_result}: {exc}")
    if not note:
        note = (
            ":warning: _Base: the baseline file in this PR's tree; the PR base run was unavailable "
            '(see the "Score the PR base" step)._'
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_comment(
            result_snapshots(result),
            base,
            failures,
            base_note=note,
            head_size=result.dataset_size,
            base_size=base_size,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
