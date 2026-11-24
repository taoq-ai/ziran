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
    uv run python benchmarks/detection_accuracy.py --crossfire --categories borderline
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ValidationError

from benchmarks.accuracy_metrics import _wilson_ci
from benchmarks.ground_truth.schema import (
    IN_SCOPE_DETECTORS,
    DetectionExample,
)
from benchmarks.replay_llm_client import ReplayLLMClient
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.ensemble import EnsembleConfig
from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.interfaces.adapter import AgentResponse, scan_metadata
from ziran.infrastructure.config.detectors import load_detector_thresholds

if TYPE_CHECKING:
    from ziran.domain.interfaces.embedder import BaseEmbedder

DATASET_DIR = Path(__file__).parent / "ground_truth" / "detection"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "detection_accuracy.json"

ORIGINAL_CATEGORIES = ("clear_refusal", "partial_compliance", "full_compliance", "borderline")
#: Harder slices (spec 078): near-miss benign text, so a false positive gain is measurable.
HARD_CATEGORIES = (
    "indicator_near_miss",
    "sensitive_tool_output",
    "paraphrased_refusal",
    "multilingual",
)
CATEGORIES = ORIGINAL_CATEGORIES + HARD_CATEGORIES
MIN_PER_CATEGORY = 50
MIN_APPLICABLE_PER_DETECTOR = 30
#: Extra detectors row (spec 042): the refusal decision with the semantic tier's veto.
SEMANTIC_REFUSAL_KEY = "refusal+semantic"


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


class CrossfireResult(BaseModel):
    """Every library vector prompt against every benign reply (spec 078)."""

    vectors: int
    prompts: int
    benign_replies: int
    pairs: int
    flagged: int
    rate: float
    vectors_with_hit: int
    #: Flagged pairs where the indicator detector hit (benign tool calls flag on side_effect).
    indicator_flagged: int
    vectors_with_indicator_hit: int
    flagged_by_category: dict[str, int]
    top_indicators: list[tuple[str, int]]


class DetectorAccuracyResult(BaseModel):
    timestamp: str
    dataset_size: int
    per_category_counts: dict[str, int]
    per_detector_applicable: dict[str, int]
    detectors: dict[str, DetectorMetrics]
    pipeline: DetectorMetrics
    below_floor: list[str] = []
    #: category -> {"pipeline" or detector name -> confusion} (spec 078).
    per_category_confusion: dict[str, dict[str, ConfusionMatrix]] = {}
    crossfire: CrossfireResult | None = None


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


def load_examples(
    dataset_dir: Path, categories: tuple[str, ...] = CATEGORIES
) -> list[DetectionExample]:
    """Load and validate every example YAML under *dataset_dir* for *categories*."""
    examples: list[DetectionExample] = []
    for category in categories:
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


def _response(ex: DetectionExample) -> AgentResponse:
    return AgentResponse(
        content=ex.response_text,
        tool_calls=[tc.model_dump(exclude_none=True) for tc in ex.tool_calls],
        metadata=ex.metadata,
    )


async def _score(
    examples: list[DetectionExample],
    thresholds: DetectorThresholds,
    *,
    embedder: BaseEmbedder | None = None,
    disabled: frozenset[str] = frozenset(),
    pipeline: DetectorPipeline | None = None,
) -> DetectorAccuracyResult:
    # A caller-built pipeline (spec 043 harness) is used as-is.
    if pipeline is None:
        # Fixtures replay one judge verdict per example, so always score the single judge.
        single = thresholds.model_copy(update={"ensemble": EnsembleConfig()})
        pipeline = DetectorPipeline(
            llm_client=ReplayLLMClient(examples),
            detector_config=DetectorConfig(thresholds=single, disabled=set(disabled)),
            embedder=embedder,
        )

    keys = list(IN_SCOPE_DETECTORS)
    if embedder is not None and thresholds.semantic.enabled and "semantic" not in disabled:
        keys.append(SEMANTIC_REFUSAL_KEY)
    det_cm: dict[str, ConfusionMatrix] = {d: ConfusionMatrix() for d in keys}
    det_applicable: dict[str, int] = dict.fromkeys(keys, 0)
    pipeline_cm = ConfusionMatrix()
    per_category: dict[str, int] = defaultdict(int)
    cat_cm: dict[str, dict[str, ConfusionMatrix]] = defaultdict(
        lambda: defaultdict(ConfusionMatrix)
    )

    for ex in examples:
        per_category[ex.category] += 1
        prompt_spec = AttackPrompt(
            template=ex.attack.vector_id,
            success_indicators=ex.prompt_success_indicators,
            failure_indicators=ex.prompt_failure_indicators,
        )
        verdict = await pipeline.evaluate(ex.attack.vector_id, _response(ex), prompt_spec)

        # Pipeline confusion vs overall label.
        pipeline_cm.add(expected=ex.label == "compromise", actual=verdict.successful)
        cat_cm[ex.category]["pipeline"].add(
            expected=ex.label == "compromise", actual=verdict.successful
        )

        # Per-detector confusion vs each detector's own expected verdict.
        results = {r.detector_name: r for r in verdict.detector_results}
        for expected in ex.expected_detectors:
            name = expected.detector
            if name not in det_cm:  # authorization and unknowns excluded
                continue
            det_applicable[name] += 1
            actual_fired = name in results and results[name].score >= thresholds.hit
            det_cm[name].add(expected=expected.should_fire, actual=actual_fired)
            cat_cm[ex.category][name].add(expected=expected.should_fire, actual=actual_fired)
            if name == "refusal" and SEMANTIC_REFUSAL_KEY in det_cm:
                sem = results.get("semantic")
                vetoed = sem is not None and sem.score == 0.0
                det_applicable[SEMANTIC_REFUSAL_KEY] += 1
                det_cm[SEMANTIC_REFUSAL_KEY].add(
                    expected=expected.should_fire, actual=actual_fired and not vetoed
                )

    below_floor = [d for d in IN_SCOPE_DETECTORS if det_applicable[d] < MIN_APPLICABLE_PER_DETECTOR]

    return DetectorAccuracyResult(
        timestamp=_now(),
        dataset_size=len(examples),
        per_category_counts=dict(per_category),
        per_detector_applicable=det_applicable,
        detectors={d: _metrics(det_cm[d], det_applicable[d]) for d in keys},
        pipeline=_metrics(pipeline_cm, pipeline_cm.total),
        below_floor=below_floor,
        per_category_confusion={c: dict(m) for c, m in cat_cm.items()},
    )


async def _crossfire(examples: list[DetectionExample]) -> CrossfireResult:
    """Run every library vector prompt's indicators over every benign reply (spec 078).

    Default ``DetectorConfig``, no judge, the vector passed, and the rendered prompt as the
    payload (study-v2.1): what a scan would flag if the agent answered that prompt with that
    benign reply. A flag is a benign call that holds a value the prompt names.
    """
    benign = [ex for ex in examples if ex.label == "no_compromise"]
    responses = [_response(ex) for ex in benign]
    vectors = AttackLibrary().vectors
    pipeline = DetectorPipeline(detector_config=DetectorConfig())
    hit = DetectorThresholds().hit
    prompts = flagged = indicator_flagged = 0
    hit_vectors: set[str] = set()
    indicator_vectors: set[str] = set()
    by_category: Counter[str] = Counter()
    by_indicator: Counter[str] = Counter()
    for vector in vectors:
        for prompt in vector.prompts:
            prompts += 1
            sent = AttackExecutor._render_prompt(prompt)
            for ex, reply in zip(benign, responses, strict=True):
                response = reply.model_copy(
                    update={"metadata": scan_metadata(reply.metadata, sent)}
                )
                verdict = await pipeline.evaluate(sent, response, prompt, vector)
                if not verdict.successful:
                    continue
                flagged += 1
                hit_vectors.add(vector.id)
                by_category[ex.category] += 1
                for r in verdict.detector_results:
                    if r.detector_name == "indicator" and r.score >= hit:
                        indicator_flagged += 1
                        indicator_vectors.add(vector.id)
                        by_indicator.update(r.matched_indicators)
    pairs = prompts * len(benign)
    return CrossfireResult(
        vectors=len(vectors),
        prompts=prompts,
        benign_replies=len(benign),
        pairs=pairs,
        flagged=flagged,
        rate=round(flagged / pairs, 4) if pairs else 0.0,
        vectors_with_hit=len(hit_vectors),
        indicator_flagged=indicator_flagged,
        vectors_with_indicator_hit=len(indicator_vectors),
        flagged_by_category=dict(by_category),
        top_indicators=by_indicator.most_common(15),
    )


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(tz=UTC).isoformat()


def run_benchmark(
    dataset_dir: Path = DATASET_DIR,
    thresholds: DetectorThresholds | None = None,
    *,
    embedder: BaseEmbedder | None = None,
    disabled: frozenset[str] = frozenset(),
    categories: tuple[str, ...] = CATEGORIES,
    crossfire: bool = False,
) -> DetectorAccuracyResult:
    """Synchronous entry point: load, score, and return the result."""
    examples = load_examples(dataset_dir, categories)
    if not examples:
        raise SystemExit(f"No examples found under {dataset_dir}")
    result = asyncio.run(
        _score(examples, thresholds or DetectorThresholds(), embedder=embedder, disabled=disabled)
    )
    if crossfire:
        result.crossfire = asyncio.run(_crossfire(examples))
    return result


# ── Coverage + rendering ──────────────────────────────────────────────


def check_coverage(
    result: DetectorAccuracyResult, *, strict: bool, categories: tuple[str, ...] = CATEGORIES
) -> list[str]:
    """Return human-readable coverage warnings; raise in strict mode if any."""
    warnings: list[str] = []
    for cat in categories:
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


def _row(name: str, m: DetectorMetrics) -> tuple[str, ...]:
    confusion = _counts(m.confusion)
    ci = f"[{m.recall_ci[0]}, {m.recall_ci[1]}]"
    return (name, str(m.applicable), f"{m.precision}", f"{m.recall}", f"{m.f1}", confusion, ci)


def render(result: DetectorAccuracyResult, *, fmt: str, by_category: bool) -> str:
    rows = [("detector", "applicable", "precision", "recall", "f1", "tp/fp/fn/tn", "recall 95% CI")]
    for name, m in result.detectors.items():
        rows.append(_row(name, m))
    rows.append(_row("PIPELINE", result.pipeline))

    if fmt == "markdown":
        head = "| " + " | ".join(rows[0]) + " |"
        sep = "| " + " | ".join("---" for _ in rows[0]) + " |"
        body = "\n".join("| " + " | ".join(r) + " |" for r in rows[1:])
        out = "\n".join([head, sep, body])
    else:
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        out = "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows)

    if by_category:
        counts = ", ".join(f"{c}={n}" for c, n in result.per_category_counts.items())
        out += f"\n\nPer-category counts: {counts}"
        out += "\n\nPer-category tp/fp/fn/tn:"
        for cat, cms in result.per_category_confusion.items():
            cells = ", ".join(f"{name} {_counts(cm)}" for name, cm in cms.items())
            out += f"\n  {cat}: {cells}"
    cf = result.crossfire
    if cf is not None:
        top = ", ".join(f"{w} {n}" for w, n in cf.top_indicators)
        out += (
            f"\n\nCrossfire: {cf.flagged} of {cf.pairs} pairs flagged (rate {cf.rate}); "
            f"{cf.vectors_with_hit} of {cf.vectors} vectors ({cf.prompts} prompts) hit "
            f"{cf.benign_replies} benign replies\n  indicator hits: {cf.indicator_flagged} pairs, "
            f"{cf.vectors_with_indicator_hit} vectors\n  top indicators: {top}"
        )
    return out


def _counts(cm: ConfusionMatrix) -> str:
    return f"{cm.tp}/{cm.fp}/{cm.fn}/{cm.tn}"


# ── CLI ───────────────────────────────────────────────────────────────


def _categories(value: str) -> tuple[str, ...]:
    names = tuple(value.split(","))
    unknown = [n for n in names if n not in CATEGORIES]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown categories {unknown}; choose from {', '.join(CATEGORIES)}"
        )
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZIRAN detection-accuracy benchmark")
    parser.add_argument("--json", type=Path, default=DEFAULT_OUTPUT, help="Result JSON path")
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR, help="Dataset root")
    parser.add_argument("--config", type=Path, default=None, help="Threshold config YAML")
    parser.add_argument("--by-category", action="store_true", help="Show per-category counts")
    parser.add_argument("--format", choices=("table", "markdown"), default="table")
    parser.add_argument("--strict", action="store_true", help="Fail if coverage floors are not met")
    parser.add_argument(
        "--categories",
        type=_categories,
        default=CATEGORIES,
        help="Comma-separated categories to load (default: all)",
    )
    parser.add_argument(
        "--crossfire", action="store_true", help="Also run every library prompt on benign replies"
    )
    args = parser.parse_args(argv)

    # load_detector_thresholds defaults to .ziran/detectors.yaml when --config is
    # omitted, and returns built-in defaults when that file is absent (CLI contract).
    thresholds = load_detector_thresholds(args.config)
    result = run_benchmark(
        args.dataset, thresholds, categories=args.categories, crossfire=args.crossfire
    )

    warnings = check_coverage(result, strict=args.strict, categories=args.categories)
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
