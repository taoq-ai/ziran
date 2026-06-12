"""Detection-accuracy regression gate (spec 021, US3).

Compares the current pipeline F1 against a recorded baseline and fails when it
drops more than a fixed absolute tolerance (default 0.02). Per-detector F1
deltas are reported for visibility but never cause failure (clarification Q3).

Usage:
    uv run python benchmarks/detection_regression.py
    uv run python benchmarks/detection_regression.py --update-baseline
    uv run python benchmarks/detection_regression.py --format markdown

Exit codes:
    0  pass (F1 within tolerance, or baseline updated)
    1  regression beyond tolerance
    2  baseline missing (run with --update-baseline to create it)
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from benchmarks.detection_accuracy import DATASET_DIR, DetectorAccuracyResult, run_benchmark

BASELINE_PATH = Path(__file__).parent / "results" / "detection_accuracy_baseline.json"
DEFAULT_TOLERANCE = 0.02


class DetectionAccuracyBaseline(BaseModel):
    """Recorded reference the regression gate compares against."""

    timestamp: str
    pipeline_f1: float
    tolerance: float = DEFAULT_TOLERANCE
    per_detector_f1: dict[str, float]
    dataset_size: int

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
        )


def _render(
    baseline: DetectionAccuracyBaseline,
    result: DetectorAccuracyResult,
    *,
    regressed: bool,
    fmt: str,
) -> str:
    delta = round(result.pipeline.f1 - baseline.pipeline_f1, 4)
    status = "REGRESSION" if regressed else "OK"
    lines = [
        f"Detection-accuracy gate: {status}",
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
    regressed = (baseline.pipeline_f1 - result.pipeline.f1) > baseline.tolerance
    print(_render(baseline, result, regressed=regressed, fmt=args.format))
    return 1 if regressed else 0


if __name__ == "__main__":
    raise SystemExit(main())
