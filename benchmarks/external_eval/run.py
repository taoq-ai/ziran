"""External detection evaluation harness (spec 062; ziran-paper prereg/ext-eval-protocol.md).

Scores ziran's response detectors on one benchmark against the benchmark's own labels, at each
ziran pin, in a fresh worker process per pin. Writes only counts, hashes, unit ids, labels and
verdicts: ``<out>/<benchmark>.rows.jsonl`` and ``<out>/<benchmark>.summary.json``.

Usage (from any folder; ``-I`` is required)::

    uv run --frozen python -I benchmarks/external_eval/run.py --benchmark agentdojo \\
        --data <intake folder> --manifest <manifest.json> --ziran-repo <ziran clone> \\
        --pin study-v1=<sha> --pin study-v0=b813e4f --out <git-ignored folder>

Exit codes: 0 evaluated, 2 refused (flags, paths, pins, worker), 3 not evaluated (intake failed,
protocol section 10).
"""

from __future__ import annotations

import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[2]
if str(HARNESS_ROOT) not in sys.path:  # -I leaves the script's folder off sys.path
    sys.path.insert(0, str(HARNESS_ROOT))

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
from collections import defaultdict  # noqa: E402
from typing import Any  # noqa: E402

from benchmarks.external_eval import isolation, metrics  # noqa: E402
from benchmarks.external_eval.collect import PRIMARY, Collected, collect  # noqa: E402
from benchmarks.external_eval.intake import (  # noqa: E402
    HarnessError,
    IntakeError,
    read_manifest,
    require_outside_or_ignored,
    sha256,
)
from benchmarks.external_eval.worker import block_sockets  # noqa: E402

WORKER = Path(__file__).resolve().parent / "worker.py"
PREDICTORS = ("refusal", "side_effect", "pipeline")
EXPLORATORY_BELOW = 50
PROTOCOL = {
    "repository": "taoq-ai/ziran-paper",
    "file": "prereg/ext-eval-protocol.md",
    "built_against": "cbf25bd72e5e7bf73ac373341585b15d3bf90c08",
}


def _args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--benchmark", required=True, choices=sorted(PRIMARY))
    p.add_argument("--data", required=True, type=Path, help="intake folder of the benchmark")
    p.add_argument("--manifest", required=True, type=Path, help="sha256 manifest (JSON)")
    p.add_argument("--ziran-repo", required=True, type=Path, help="ziran clone holding the pins")
    p.add_argument("--pin", required=True, action="append", help="NAME=REV, once per pin")
    p.add_argument("--out", required=True, type=Path, help="output folder, git-ignored or outside")
    p.add_argument("--practice", action="store_true", help="allow uncommitted harness files")
    return p.parse_args(argv)


def _pins(repo: Path, specs: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for spec in specs:
        name, sep, rev = spec.partition("=")
        if not sep or not name or not rev or name in pins:
            raise HarnessError(f"--pin {spec!r} is not a new NAME=REV")
        pins[name] = isolation.resolve_sha(repo, rev)
    return pins


def _worker(
    export: Path, cwd: Path, units: Collected
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run one fresh worker on every unit; its stderr is kept and never printed."""
    payload = "".join(
        json.dumps({"key": i, "prompt": u.prompt, "content": u.content, "tool_calls": u.tool_calls})
        + "\n"
        for i, u in enumerate(units.units)
    )
    proc = subprocess.run(
        [sys.executable, "-I", str(WORKER), str(export)],
        input=payload, capture_output=True, text=True, env=isolation.worker_env(), cwd=cwd,
        check=False,
    )  # fmt: skip
    if proc.returncode != 0:
        raise HarnessError(f"worker exited {proc.returncode}")
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    if len(lines) < 2 or "header" not in lines[0] or lines[-1].get("end") != len(units.units):
        raise HarnessError("worker output is incomplete")
    verdicts = lines[1:-1]
    if [v["key"] for v in verdicts] != list(range(len(units.units))):
        raise HarnessError("worker verdicts are out of order")
    header = {"defaults": lines[0]["header"], "modules_checked": lines[-1]["modules"]}
    return header, verdicts


def _block(pairs: list[tuple[bool, bool]]) -> dict[str, Any]:
    c = metrics.confusion(pairs)
    return {
        "confusion": c.model_dump(),
        **{k: v.model_dump() for k, v in metrics.x_metrics(c).items()},
        "exploratory": len(pairs) < EXPLORATORY_BELOW,
    }


def _metrics(units: Collected, verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """X1 to X4 per variant and predictor, pooled and per cell (protocol sections 6, 7)."""
    out: dict[str, Any] = {}
    variants = sorted({u.variant for u in units.units})
    for variant in variants:
        out[variant] = {}
        for pred in PREDICTORS:
            pooled: list[tuple[bool, bool]] = []
            cells: dict[str, dict[str, list[tuple[bool, bool]]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for u, v in zip(units.units, verdicts, strict=True):
                if u.variant != variant or u.excluded is not None or u.label is None:
                    continue
                pair = (u.label, bool(v[pred]))
                pooled.append(pair)
                for key, value in u.cells.items():
                    cells[key][value].append(pair)
            out[variant][pred] = {
                "all": _block(pooled),
                "cells": {
                    key: {value: _block(p) for value, p in sorted(vals.items())}
                    for key, vals in sorted(cells.items())
                },
            }
    return out


def _bootstrap(units: Collected, verdicts: list[dict[str, Any]], pred: str) -> dict[str, Any]:
    analysed = [
        (u.cluster, u.label, bool(v[pred]))
        for u, v in zip(units.units, verdicts, strict=True)
        if u.variant == "whole" and u.excluded is None and u.label is not None
    ]
    return {k: list(v) if v else None for k, v in metrics.cluster_bootstrap(analysed).items()}


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return sha256(text.encode())


def run(args: argparse.Namespace, removed: int) -> int:
    for path in (args.data, args.out):
        require_outside_or_ignored(HARNESS_ROOT, path)
        require_outside_or_ignored(args.ziran_repo, path)
    harness = isolation.harness_record(HARNESS_ROOT, args.practice)
    pins = _pins(args.ziran_repo, args.pin)
    args.out.mkdir(parents=True, exist_ok=True)
    bench = args.benchmark
    summary: dict[str, Any] = {
        "benchmark": bench,
        "protocol": PROTOCOL,
        "harness": harness,
        "environment_variables_removed": removed,
        "pins": {name: {"sha": sha} for name, sha in pins.items()},
        "primary": PRIMARY[bench],
    }
    summary_path = args.out / f"{bench}.summary.json"
    try:
        if args.manifest.is_file():
            summary["manifest_sha256"] = sha256(args.manifest.read_bytes())
        units = collect(bench, args.data, read_manifest(args.manifest))
    except IntakeError as exc:
        summary |= {"status": "not_evaluated", "reason": str(exc)}
        digest = _write(summary_path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"benchmark": bench, "status": "not_evaluated", "summary_sha256": digest}))
        return 3
    summary["intake"] = {
        "counts": units.counts,
        "spdx": units.spdx,
        "terms_spdx": units.terms_spdx,
        "manifest_files": units.manifest_files,
        "extra_sha256": units.extra_hashes,
    }
    rows: list[str] = []
    summary["metrics"], summary["bootstrap"] = {}, {}
    for name, sha in pins.items():
        with tempfile.TemporaryDirectory(prefix="ext-eval-") as tmp:
            export, cwd = Path(tmp) / "ziran", Path(tmp) / "cwd"
            export.mkdir()
            cwd.mkdir()
            isolation.export_pin(args.ziran_repo, sha, export)
            summary["pins"][name]["files_sha256"] = isolation.file_hashes(
                export, isolation.PINNED_FILES
            )
            header, verdicts = _worker(export.resolve(), cwd, units)
        summary["pins"][name] |= header
        summary["metrics"][name] = _metrics(units, verdicts)
        summary["bootstrap"][name] = _bootstrap(units, verdicts, PRIMARY[bench])
        for u, v in zip(units.units, verdicts, strict=True):
            row = {
                "benchmark": bench, "pin": name, "unit_id": u.unit_id, "variant": u.variant,
                "label": u.label, "excluded": u.excluded, "cells": u.cells,
                **{p: bool(v[p]) for p in PREDICTORS},
            }  # fmt: skip
            rows.append(json.dumps(row, sort_keys=True) + "\n")
    summary["status"] = "evaluated"
    summary["rows_sha256"] = _write(args.out / f"{bench}.rows.jsonl", "".join(rows))
    digest = _write(summary_path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "benchmark": bench,
                "status": "evaluated",
                "counts": units.counts,
                "rows": len(rows),
                "rows_sha256": summary["rows_sha256"],
                "summary_sha256": digest,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        isolation.require_interpreter_flags()
        if any(name.split(".")[0] == "ziran" for name in sys.modules):
            raise HarnessError("ziran is loaded in the harness process; only workers load it")
        removed = isolation.scrub_environ(os.environ)
        block_sockets()
        return run(_args(argv), removed)
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
