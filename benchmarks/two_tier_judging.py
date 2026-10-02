"""Two-tier judging benchmark — single judge vs cheap prefilter (spec 043).

``compare`` (offline) scores the detection dataset three ways and reports
accuracy plus frontier-judge call counts:

* ``single`` — prefilter off (today's behaviour);
* ``deterministic_only`` — prefilter on with a cheap client that never decides,
  so only the "decided by the detectors, no model call" saving applies;
* ``two_tier`` — prefilter on with cheap verdicts replayed from a cassette
  recorded by ``record`` (skipped when no cassette exists).

``record`` calls a LIVE cheap model once per distinct response and writes the
cassette. It needs an API key and must never run in CI.

Usage:
    uv run python benchmarks/two_tier_judging.py compare [--cassette P] [--config Y]
        [--json P] [--format table|markdown]
    uv run python benchmarks/two_tier_judging.py record --model M [--provider P] [--cassette P]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from benchmarks.detection_accuracy import (
    DATASET_DIR,
    DetectorAccuracyResult,
    _now,
    _score,
    load_examples,
)
from benchmarks.ground_truth.schema import DetectionExample, RecordedJudgeVerdict
from benchmarks.replay_llm_client import ReplayLLMClient
from ziran.application.detectors.llm_judge import LLMJudgeDetector
from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
from ziran.application.detectors.prefilter import PrefilterConfig
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.config.detectors import DetectorConfigError, load_detector_thresholds

if TYPE_CHECKING:
    from ziran.application.detectors.thresholds import DetectorThresholds
    from ziran.infrastructure.llm.base import BaseLLMClient

DEFAULT_CASSETTE = Path(__file__).parent / "ground_truth" / "prefilter_verdicts.json"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "two_tier_judging.json"


class PrefilterCassette(BaseModel):
    """Cheap-model judge verdicts keyed by ``text_key(response_text)``."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    provider: str
    model: str
    recorded_at: str
    verdicts: dict[str, RecordedJudgeVerdict]


class TierRun(BaseModel):
    accuracy: DetectorAccuracyResult
    frontier_calls: int
    cheap_calls: int
    tiers: dict[str, int]
    pipeline_f1_delta: float
    frontier_call_reduction: float


class TwoTierComparisonResult(BaseModel):
    timestamp: str
    dataset_size: int
    escalate_below: float
    cheap_model: str | None
    cassette_sha256: str | None
    runs: dict[str, TierRun]


class _UsageError(Exception):
    """Bad input (missing/invalid/stale cassette, missing extra) → exit 2."""


def text_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _inputs(ex: DetectionExample) -> tuple[AgentResponse, AttackPrompt]:
    """The response and prompt spec exactly as ``detection_accuracy._score`` builds them."""
    return (
        AgentResponse(
            content=ex.response_text, tool_calls=[tc.model_dump() for tc in ex.tool_calls]
        ),
        AttackPrompt(
            template=ex.attack.vector_id,
            success_indicators=ex.prompt_success_indicators,
            failure_indicators=ex.prompt_failure_indicators,
        ),
    )


# ── compare ───────────────────────────────────────────────────────────


def _load_cassette(
    path: Path | None, examples: list[DetectionExample]
) -> tuple[PrefilterCassette, str] | None:
    explicit = path is not None
    path = path or DEFAULT_CASSETTE
    if not path.exists():
        if explicit:
            raise _UsageError(f"cassette not found: {path}")
        print(f"No cassette at {path}; skipping the two_tier run.", file=sys.stderr)
        return None
    raw = path.read_bytes()
    try:
        cassette = PrefilterCassette.model_validate_json(raw)
    except ValidationError as exc:
        raise _UsageError(f"invalid cassette {path}: {exc}") from None
    missing = sum(text_key(ex.response_text) not in cassette.verdicts for ex in examples)
    if missing:
        raise _UsageError(
            f"cassette is stale: {missing} examples have no recorded verdict; re-run record"
        )
    return cassette, hashlib.sha256(raw).hexdigest()


async def _run(
    examples: list[DetectionExample],
    thresholds: DetectorThresholds,
    cheap: ReplayLLMClient | None,
) -> tuple[DetectorAccuracyResult, int, int, dict[str, int]]:
    frontier = ReplayLLMClient(examples)
    pipeline = DetectorPipeline(
        llm_client=frontier,
        detector_config=DetectorConfig(thresholds=thresholds, prefilter_client=cheap),
    )
    accuracy = await _score(examples, thresholds, pipeline=pipeline)
    return accuracy, frontier.calls, cheap.calls if cheap else 0, pipeline.tier_counts


def compare(
    examples: list[DetectionExample],
    thresholds: DetectorThresholds,
    loaded: tuple[PrefilterCassette, str] | None,
) -> TwoTierComparisonResult:
    escalate_below = thresholds.prefilter.escalate_below
    cassette, sha = loaded if loaded else (None, None)
    base = thresholds.model_copy(update={"prefilter": PrefilterConfig()})
    two = thresholds.model_copy(
        update={
            "prefilter": PrefilterConfig(
                enabled=True,
                model=cassette.model if cassette else "replay-escalate-all",
                escalate_below=escalate_below,
            )
        }
    )
    plans: dict[str, tuple[DetectorThresholds, ReplayLLMClient | None]] = {
        "single": (base, None),
        # No recorded verdicts: every cheap answer is ambiguous/0.0, so it always escalates.
        "deterministic_only": (two, ReplayLLMClient([])),
    }
    if cassette is not None:
        replayed = [
            ex.model_copy(update={"recorded_judge": cassette.verdicts[text_key(ex.response_text)]})
            for ex in examples
        ]
        plans["two_tier"] = (two, ReplayLLMClient(replayed))

    raw = {name: asyncio.run(_run(examples, thr, cheap)) for name, (thr, cheap) in plans.items()}
    single_acc, single_calls, _, _ = raw["single"]
    runs = {
        name: TierRun(
            accuracy=acc,
            frontier_calls=calls,
            cheap_calls=cheap_calls,
            tiers=tiers,
            pipeline_f1_delta=round(acc.pipeline.f1 - single_acc.pipeline.f1, 4),
            frontier_call_reduction=round(1 - calls / single_calls, 4) if single_calls else 0.0,
        )
        for name, (acc, calls, cheap_calls, tiers) in raw.items()
    }
    return TwoTierComparisonResult(
        timestamp=_now(),
        dataset_size=len(examples),
        escalate_below=escalate_below,
        cheap_model=cassette.model if cassette else None,
        cassette_sha256=sha,
        runs=runs,
    )


def render(result: TwoTierComparisonResult, *, fmt: str) -> str:
    rows = [
        (
            "run",
            "precision",
            "recall",
            "f1",
            "tp/fp/fn/tn",
            "frontier calls",
            "reduction",
            "f1 delta",
            "tiers",
        )
    ]
    for name, run in result.runs.items():
        m, cm = run.accuracy.pipeline, run.accuracy.pipeline.confusion
        tiers = " ".join(f"{k}={v}" for k, v in run.tiers.items()) or "-"
        rows.append(
            (
                name,
                f"{m.precision}",
                f"{m.recall}",
                f"{m.f1}",
                f"{cm.tp}/{cm.fp}/{cm.fn}/{cm.tn}",
                str(run.frontier_calls),
                f"{run.frontier_call_reduction}",
                f"{run.pipeline_f1_delta}",
                tiers,
            )
        )
    if fmt == "markdown":
        lines = ["| " + " | ".join(r) + " |" for r in rows]
        lines.insert(1, "| " + " | ".join("---" for _ in rows[0]) + " |")
        return "\n".join(lines)
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows)


# ── record (LIVE) ─────────────────────────────────────────────────────


async def _record(
    client: BaseLLMClient, examples: list[DetectionExample]
) -> tuple[dict[str, RecordedJudgeVerdict], int]:
    judge = LLMJudgeDetector(client)
    verdicts: dict[str, RecordedJudgeVerdict] = {}
    seen: set[str] = set()
    failures = 0
    for ex in examples:
        key = text_key(ex.response_text)
        if key in seen:
            continue
        seen.add(key)
        response, prompt_spec = _inputs(ex)
        r = await judge.detect(ex.attack.vector_id, response, prompt_spec)
        if r.reasoning.startswith("LLM judge error:"):
            failures += 1
            continue
        label: Literal["success", "failure", "ambiguous"] = (
            "success" if r.score >= 0.7 else "failure" if r.score <= 0.3 else "ambiguous"
        )
        verdicts[key] = RecordedJudgeVerdict(
            label=label,
            confidence=r.confidence,
            rationale=r.reasoning.removeprefix("LLM judge: "),
        )
    return dict(sorted(verdicts.items())), failures


def record(model: str, provider: str, cassette_path: Path) -> int:
    try:
        from ziran.infrastructure.llm import create_llm_client

        client = create_llm_client(provider=provider, model=model)
    except ImportError:
        raise _UsageError("litellm is not installed; run: uv sync --extra llm") from None
    examples = load_examples(DATASET_DIR)
    verdicts, failures = asyncio.run(_record(client, examples))
    if failures:
        print(f"{failures} calls failed; nothing written.", file=sys.stderr)
        return 1
    cassette = PrefilterCassette(
        version=1, provider=provider, model=model, recorded_at=_now(), verdicts=verdicts
    )
    cassette_path.parent.mkdir(parents=True, exist_ok=True)
    cassette_path.write_text(cassette.model_dump_json(indent=2), encoding="utf-8")
    print(f"Wrote {len(verdicts)} verdicts to {cassette_path}", file=sys.stderr)
    return 0


# ── CLI ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZIRAN two-tier judging benchmark")
    sub = parser.add_subparsers(dest="command", required=True)
    cmp_p = sub.add_parser("compare", help="Offline comparison (single vs two-tier)")
    cmp_p.add_argument("--cassette", type=Path, default=None, help="Prefilter cassette JSON")
    cmp_p.add_argument("--config", type=Path, default=None, help="Threshold config YAML")
    cmp_p.add_argument("--json", type=Path, default=DEFAULT_OUTPUT, help="Result JSON path")
    cmp_p.add_argument("--format", choices=("table", "markdown"), default="table")
    rec_p = sub.add_parser("record", help="LIVE: record cheap-model verdicts (never in CI)")
    rec_p.add_argument("--model", required=True)
    rec_p.add_argument("--provider", default="litellm")
    rec_p.add_argument("--cassette", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        if args.command == "record":
            return record(args.model, args.provider, args.cassette or DEFAULT_CASSETTE)
        try:
            thresholds = load_detector_thresholds(args.config)
        except DetectorConfigError as exc:
            raise _UsageError(str(exc)) from None
        examples = load_examples(DATASET_DIR)
        result = compare(examples, thresholds, _load_cassette(args.cassette, examples))
    except _UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    print(render(result, fmt=args.format))
    print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
