"""Semantic-tier comparison on the detection-accuracy dataset (spec 042).

``record`` embeds every text the comparison needs with a real embedding model
(via litellm, the ``llm`` extra) and writes a cassette keyed by SHA-256 of the
text. ``compare`` replays that cassette offline and reports the regex pipeline
against the pipeline with the semantic tier, with and without the LLM judge.
Not a CI gate; ``record`` is never run in CI.

Usage:
    uv run python benchmarks/semantic_detection.py record --model ollama/nomic-embed-text \\
        --base-url http://localhost:11434
    uv run python benchmarks/semantic_detection.py compare --format markdown
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError, field_serializer

from benchmarks.detection_accuracy import (
    DATASET_DIR,
    SEMANTIC_REFUSAL_KEY,
    DetectorAccuracyResult,
    DetectorMetrics,
    load_examples,
    run_benchmark,
)
from benchmarks.replay_embedder import EmbeddingCassette, ReplayEmbedder, text_key
from ziran.application.detectors.semantic import (
    REFUSAL_EXEMPLARS,
    SUCCESS_EXEMPLARS,
    SemanticConfig,
    embedding_input,
)
from ziran.infrastructure.config.detectors import load_detector_thresholds

DEFAULT_CASSETTE = Path(__file__).parent / "ground_truth" / "semantic_embeddings.json"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "semantic_detection_comparison.json"
_BATCH = 64


class SemanticComparisonResult(BaseModel):
    timestamp: str
    model: str
    cassette_sha256: str
    semantic: SemanticConfig
    runs: dict[str, DetectorAccuracyResult]

    @field_serializer("semantic")
    def _drop_base_url(self, cfg: SemanticConfig) -> dict[str, object]:
        # A base_url may embed credentials; keep it out of committed artifacts.
        return cfg.model_dump(exclude={"base_url"})


def needed_texts(cfg: SemanticConfig) -> list[str]:
    """Every distinct, non-empty text the comparison embeds, in a stable order."""
    texts = [*REFUSAL_EXEMPLARS, *SUCCESS_EXEMPLARS]
    texts += [embedding_input(ex.response_text, cfg.max_chars) for ex in load_examples(DATASET_DIR)]
    return [t for t in dict.fromkeys(texts) if t]


def _record(args: argparse.Namespace) -> int:
    from ziran.infrastructure.llm.embedding import LiteLLMEmbedder

    cfg = load_detector_thresholds(args.config).semantic
    try:
        embedder = LiteLLMEmbedder(args.model, base_url=args.base_url, api_key_env=args.api_key_env)
    except ImportError:
        print("litellm is not installed. Run: uv sync --extra llm", file=sys.stderr)
        return 2

    texts = needed_texts(cfg)

    async def _embed_all() -> list[list[float]]:
        vectors: list[list[float]] = []
        for i in range(0, len(texts), _BATCH):
            vectors += await embedder.embed(texts[i : i + _BATCH])
        return vectors

    try:
        vectors = asyncio.run(_embed_all())
    except Exception as exc:
        print(f"embedding failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    cassette = EmbeddingCassette(
        version=1,
        model=args.model,
        recorded_at=datetime.now(tz=UTC).isoformat(),
        vectors={
            text_key(t): [round(x, 6) for x in v]
            for t, v in sorted(zip(texts, vectors, strict=True), key=lambda tv: text_key(tv[0]))
        },
    )
    args.cassette.parent.mkdir(parents=True, exist_ok=True)
    args.cassette.write_text(cassette.model_dump_json(), encoding="utf-8")
    print(f"Wrote {len(cassette.vectors)} vectors to {args.cassette}", file=sys.stderr)
    return 0


def _row(name: str, m: DetectorMetrics) -> tuple[str, ...]:
    cm = m.confusion
    return (name, f"{m.precision}", f"{m.recall}", f"{m.f1}", f"{cm.tp}/{cm.fp}/{cm.fn}/{cm.tn}")


def render(result: SemanticComparisonResult, fmt: str) -> str:
    runs = result.runs
    rows = [
        ("row", "precision", "recall", "f1", "tp/fp/fn/tn"),
        _row("refusal (regex)", runs["regex"].detectors["refusal"]),
        _row(SEMANTIC_REFUSAL_KEY, runs["semantic"].detectors[SEMANTIC_REFUSAL_KEY]),
        _row("pipeline", runs["regex"].pipeline),
        _row("pipeline (semantic)", runs["semantic"].pipeline),
        _row("pipeline no-judge", runs["regex_no_judge"].pipeline),
        _row("pipeline no-judge (semantic)", runs["semantic_no_judge"].pipeline),
    ]
    if fmt == "markdown":
        lines = ["| " + " | ".join(r) + " |" for r in rows]
        lines.insert(1, "| " + " | ".join("---" for _ in rows[0]) + " |")
        return "\n".join(lines)
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows)


def _compare(args: argparse.Namespace) -> int:
    try:
        raw = args.cassette.read_bytes()
        cassette = EmbeddingCassette.model_validate_json(raw)
    except (OSError, ValidationError) as exc:
        print(f"cannot load cassette {args.cassette}: {type(exc).__name__}", file=sys.stderr)
        return 2

    base = load_detector_thresholds(args.config)
    regex = base.model_copy(
        update={"semantic": base.semantic.model_copy(update={"enabled": False})}
    )
    sem = base.model_copy(update={"semantic": base.semantic.model_copy(update={"enabled": True})})
    replay = ReplayEmbedder(cassette)
    missing = replay.missing(needed_texts(sem.semantic))
    if missing:
        print(
            f"cassette is stale: {len(missing)} texts have no recorded vector; re-run record",
            file=sys.stderr,
        )
        return 2

    no_judge = frozenset({"llm_judge"})
    result = SemanticComparisonResult(
        timestamp=datetime.now(tz=UTC).isoformat(),
        model=cassette.model,
        cassette_sha256=hashlib.sha256(raw).hexdigest(),
        semantic=sem.semantic,
        runs={
            "regex": run_benchmark(DATASET_DIR, regex),
            "semantic": run_benchmark(DATASET_DIR, sem, embedder=replay),
            "regex_no_judge": run_benchmark(DATASET_DIR, regex, disabled=no_judge),
            "semantic_no_judge": run_benchmark(
                DATASET_DIR, sem, embedder=replay, disabled=no_judge
            ),
        },
    )
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    print(render(result, args.format))
    print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZIRAN semantic-tier detection comparison")
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="Embed the needed texts with a real model")
    rec.add_argument("--model", required=True, help="litellm embedding model string")
    rec.add_argument("--base-url", default=None, help="Provider base URL (litellm api_base)")
    rec.add_argument("--api-key-env", default=None, help="Env var NAME holding the API key")
    rec.add_argument("--cassette", type=Path, default=DEFAULT_CASSETTE)
    rec.add_argument("--config", type=Path, default=None, help="Threshold config YAML")

    cmp_ = sub.add_parser("compare", help="Replay the cassette and compare regex vs semantic")
    cmp_.add_argument("--cassette", type=Path, default=DEFAULT_CASSETTE)
    cmp_.add_argument("--config", type=Path, default=None, help="Threshold config YAML")
    cmp_.add_argument("--json", type=Path, default=DEFAULT_OUTPUT, help="Result JSON path")
    cmp_.add_argument("--format", choices=("table", "markdown"), default="table")

    args = parser.parse_args(argv)
    return _record(args) if args.command == "record" else _compare(args)


if __name__ == "__main__":
    raise SystemExit(main())
