"""Detection-accuracy benchmark — run the real detector pipeline offline (spec 021).

Loads the labelled detection dataset, runs every example through the actual
``DetectorPipeline`` (with llm_judge verdicts replayed from fixtures), and
reports precision / recall / F1 + confusion matrix per in-scope detector and
for the overall pipeline verdict.

Usage:
    uv run python benchmarks/detection_accuracy.py
    uv run python benchmarks/detection_accuracy.py --json results/detection_accuracy.json
    uv run python benchmarks/detection_accuracy.py --by-category --format markdown
    uv run python benchmarks/detection_accuracy.py --config .ziran/detectors.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError

from benchmarks.accuracy_metrics import _wilson_ci
from benchmarks.ground_truth.schema import (
    IN_SCOPE_DETECTORS,
    DetectionExample,
)
from benchmarks.replay_llm_client import ReplayLLMClient
from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.config.detectors import load_detector_thresholds

DATASET_DIR = Path(__file__).parent / "ground_truth" / "detection"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "detection_accuracy.json"

CATEGORIES = ("clear_refusal", "partial_compliance", "full_compliance", "borderline")
MIN_PER_CATEGORY = 50
MIN_APPLICABLE_PER_DETECTOR = 30


# ── Result models ─────────────────────────────────────────────────────


class ConfusionMatrix(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, *, expected: bool, actual: bool) -> None:
        if expected and actual:
            self.tp += 1
        elif not expected and actual:
            self.fp += 1
        elif expected and not actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


class DetectorMetrics(BaseModel):
    applicable: int
    confusion: ConfusionMatrix
    precision: float
    recall: float
    f1: float
    recall_ci: tuple[float, float]


class DetectorAccuracyResult(BaseModel):
    timestamp: str
    dataset_size: int
    per_category_counts: dict[str, int]
    per_detector_applicable: dict[str, int]
    detectors: dict[str, DetectorMetrics]
    pipeline: DetectorMetrics
    below_floor: list[str] = []


# ── Metric math ───────────────────────────────────────────────────────


def _prf(cm: ConfusionMatrix) -> tuple[float, float, float]:
    precision = cm.tp / (cm.tp + cm.fp) if (cm.tp + cm.fp) else 0.0
    recall = cm.tp / (cm.tp + cm.fn) if (cm.tp + cm.fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)


def _metrics(cm: ConfusionMatrix, applicable: int) -> DetectorMetrics:
    precision, recall, f1 = _prf(cm)
    return DetectorMetrics(
        applicable=applicable,
        confusion=cm,
        precision=precision,
        recall=recall,
        f1=f1,
        recall_ci=_wilson_ci(cm.tp, cm.tp + cm.fn),
    )


# ── Dataset loading ───────────────────────────────────────────────────


def load_examples(dataset_dir: Path) -> list[DetectionExample]:
    """Load and validate every example YAML under *dataset_dir*."""
    examples: list[DetectionExample] = []
    for category in CATEGORIES:
        cat_dir = dataset_dir / category
        if not cat_dir.is_dir():
            continue
        for yaml_file in sorted(cat_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                examples.append(DetectionExample(**data))
            except (ValidationError, yaml.YAMLError, TypeError) as exc:
                raise SystemExit(f"Invalid example {yaml_file}: {exc}") from exc
    return examples


# ── Pipeline execution ────────────────────────────────────────────────


async def _score(
    examples: list[DetectionExample], thresholds: DetectorThresholds
) -> DetectorAccuracyResult:
    replay = ReplayLLMClient(examples)
    pipeline = DetectorPipeline(
        llm_client=replay,
        detector_config=DetectorConfig(thresholds=thresholds),
    )

    det_cm: dict[str, ConfusionMatrix] = {d: ConfusionMatrix() for d in IN_SCOPE_DETECTORS}
    det_applicable: dict[str, int] = dict.fromkeys(IN_SCOPE_DETECTORS, 0)
    pipeline_cm = ConfusionMatrix()
    per_category: dict[str, int] = defaultdict(int)

    for ex in examples:
        per_category[ex.category] += 1
        prompt_spec = AttackPrompt(
            template=ex.attack.vector_id,
            success_indicators=ex.prompt_success_indicators,
            failure_indicators=ex.prompt_failure_indicators,
        )
        response = AgentResponse(
            content=ex.response_text,
            tool_calls=[tc.model_dump() for tc in ex.tool_calls],
        )
        verdict = await pipeline.evaluate(ex.attack.vector_id, response, prompt_spec)

        # Pipeline confusion vs overall label.
        pipeline_cm.add(expected=ex.label == "compromise", actual=verdict.successful)

        # Per-detector confusion vs each detector's own expected verdict.
        results = {r.detector_name: r for r in verdict.detector_results}
        for expected in ex.expected_detectors:
            name = expected.detector
            if name not in det_cm:  # authorization and unknowns excluded
                continue
            det_applicable[name] += 1
            actual_fired = name in results and results[name].score >= thresholds.hit
            det_cm[name].add(expected=expected.should_fire, actual=actual_fired)

    below_floor = [d for d in IN_SCOPE_DETECTORS if det_applicable[d] < MIN_APPLICABLE_PER_DETECTOR]

    return DetectorAccuracyResult(
        timestamp=_now(),
        dataset_size=len(examples),
        per_category_counts=dict(per_category),
        per_detector_applicable=det_applicable,
        detectors={d: _metrics(det_cm[d], det_applicable[d]) for d in IN_SCOPE_DETECTORS},
        pipeline=_metrics(pipeline_cm, pipeline_cm.total),
        below_floor=below_floor,
    )


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(tz=UTC).isoformat()


def run_benchmark(
    dataset_dir: Path = DATASET_DIR,
    thresholds: DetectorThresholds | None = None,
) -> DetectorAccuracyResult:
    """Synchronous entry point: load, score, and return the result."""
    examples = load_examples(dataset_dir)
    if not examples:
        raise SystemExit(f"No examples found under {dataset_dir}")
    return asyncio.run(_score(examples, thresholds or DetectorThresholds()))


# ── Coverage + rendering ──────────────────────────────────────────────


def check_coverage(result: DetectorAccuracyResult, *, strict: bool) -> list[str]:
    """Return human-readable coverage warnings; raise in strict mode if any."""
    warnings: list[str] = []
    for cat in CATEGORIES:
        n = result.per_category_counts.get(cat, 0)
        if n < MIN_PER_CATEGORY:
            warnings.append(f"category '{cat}' has {n} examples (floor {MIN_PER_CATEGORY})")
    for det in result.below_floor:
        warnings.append(
            f"detector '{det}' has {result.per_detector_applicable[det]} applicable "
            f"examples (floor {MIN_APPLICABLE_PER_DETECTOR})"
        )
    if warnings and strict:
        raise SystemExit("Coverage floor not met:\n  " + "\n  ".join(warnings))
    return warnings


def render(result: DetectorAccuracyResult, *, fmt: str, by_category: bool) -> str:
    rows = [("detector", "applicable", "precision", "recall", "f1")]
    for name, m in result.detectors.items():
        rows.append((name, str(m.applicable), f"{m.precision}", f"{m.recall}", f"{m.f1}"))
    p = result.pipeline
    rows.append(("PIPELINE", str(p.applicable), f"{p.precision}", f"{p.recall}", f"{p.f1}"))

    if fmt == "markdown":
        head = "| " + " | ".join(rows[0]) + " |"
        sep = "| " + " | ".join("---" for _ in rows[0]) + " |"
        body = "\n".join("| " + " | ".join(r) + " |" for r in rows[1:])
        out = "\n".join([head, sep, body])
    else:
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        out = "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows)

    if by_category:
        counts = ", ".join(f"{c}={result.per_category_counts.get(c, 0)}" for c in CATEGORIES)
        out += f"\n\nPer-category counts: {counts}"
    return out


# ── CLI ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZIRAN detection-accuracy benchmark")
    parser.add_argument("--json", type=Path, default=DEFAULT_OUTPUT, help="Result JSON path")
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR, help="Dataset root")
    parser.add_argument("--config", type=Path, default=None, help="Threshold config YAML")
    parser.add_argument("--by-category", action="store_true", help="Show per-category counts")
    parser.add_argument("--format", choices=("table", "markdown"), default="table")
    parser.add_argument("--strict", action="store_true", help="Fail if coverage floors are not met")
    args = parser.parse_args(argv)

    thresholds = load_detector_thresholds(args.config) if args.config else DetectorThresholds()
    result = run_benchmark(args.dataset, thresholds)

    warnings = check_coverage(result, strict=args.strict)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    print(render(result, fmt=args.format, by_category=args.by_category))
    if warnings:
        print("\nCoverage warnings:", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)
    print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
