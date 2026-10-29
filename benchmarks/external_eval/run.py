"""External detection evaluation harness (spec 062; ziran-paper prereg/ext-eval-protocol.md).

Scores ziran's response detectors on one benchmark against the benchmark's own labels, at each
ziran pin, in a fresh worker process per pin. Writes only counts, hashes, unit ids, labels and
verdicts: ``<out>/<benchmark>.rows.jsonl`` and ``<out>/<benchmark>.summary.json``.

Usage (from any folder; ``-I`` is required)::

    uv run --frozen python -I benchmarks/external_eval/run.py --benchmark agentdojo \\
        --data <intake folder> --manifest <manifest.json> --ziran-repo <ziran clone> \\
        --pin study-v1=<sha> --pin study-v0=b813e4f --out <git-ignored folder>

Exit codes: 0 evaluated; 2 refused, with no summary (flags, paths, pins, --expect-harness, a
worker failure or timeout); 3 not evaluated (intake failed, protocol section 10).
"""

from __future__ import annotations

import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[2]
if str(HARNESS_ROOT) not in sys.path:  # -I leaves the script's folder off sys.path
    sys.path.insert(0, str(HARNESS_ROOT))

import argparse  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
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
from benchmarks.external_eval.worker import block_network  # noqa: E402

WORKER = Path(__file__).resolve().parent / "worker.py"
PREDICTORS = ("refusal", "side_effect", "pipeline")
EXPLORATORY_BELOW = 50
#: Seconds one pin's worker may take; a scored unit takes milliseconds.
WORKER_TIMEOUT = 3600.0
#: Bytes the worker's stderr may hold; logging only, so far above any real run.
STDERR_LIMIT = 100_000_000
_POLL_SECONDS = 0.5
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
    p.add_argument("--expect-split", type=int, help="split count from the intake addendum")
    p.add_argument("--expect-harness", help="harness commit from the intake addendum")
    p.add_argument(
        "--worker-timeout", type=_timeout, default=WORKER_TIMEOUT, help="seconds per pin worker"
    )
    return p.parse_args(argv)


def _pins(repo: Path, specs: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for spec in specs:
        name, sep, rev = spec.partition("=")
        if not sep or not name or not rev or name in pins:
            raise HarnessError(f"--pin {spec!r} is not a new NAME=REV")
        pins[name] = isolation.resolve_sha(repo, rev)
    return pins


class WorkerTimeoutError(HarnessError):
    """A worker that runs past ``--worker-timeout``; the run stops with exit 2."""


def _worker(
    export: Path, cwd: Path, units: Collected, timeout: float
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run one fresh worker on every unit; its stderr is kept and never printed.

    stdin, stdout and stderr are temporary files, not pipes, so neither side can block on a
    full pipe and the timeout waits on the process alone. The worker's whole process group is
    killed on every way out of the wait: a timeout (exit 2, no summary), Ctrl-C, SIGTERM or
    SIGHUP to the harness (``main`` turns the last two into ``SystemExit``), a verdict or stderr
    file past its cap, and normal exit. SIGKILL to the harness cannot be handled.
    """
    payload = "".join(
        json.dumps({"key": i, "prompt": u.prompt, "content": u.content, "tool_calls": u.tool_calls})
        + "\n"
        for i, u in enumerate(units.units)
    ).encode()
    with (
        tempfile.TemporaryFile() as stdin,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        stdin.write(payload)
        stdin.seek(0)
        started = time.monotonic()
        proc = subprocess.Popen(
            [sys.executable, "-I", str(WORKER), str(export)],
            stdin=stdin, stdout=stdout, stderr=stderr, env=isolation.worker_env(), cwd=cwd,
            start_new_session=True,
        )  # fmt: skip
        try:
            limit = _output_limit(len(units.units))
            returncode = _wait(proc, timeout, stdout.fileno(), limit, stderr.fileno())
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            raise WorkerTimeoutError(f"worker timed out after {timeout:g} s") from None
        except BaseException:  # Ctrl-C, a stderr flood, anything: never leave the worker running
            _kill_group(proc)
            raise
        _kill_group(proc)  # the worker exited; no grandchild outlives it
        wall = time.monotonic() - started
        if returncode != 0:
            raise HarnessError(f"worker exited {returncode}")
        stdout.seek(0)
        data = stdout.read(limit + 1)  # the bytes read, not tell(): a pin can truncate fd 1
        if len(data) > limit:
            raise HarnessError("worker output is over its size limit")
        text = data.decode("utf-8")
    lines = [json.loads(line) for line in text.splitlines()]
    if len(lines) < 2 or "header" not in lines[0] or lines[-1].get("end") != len(units.units):
        raise HarnessError("worker output is incomplete")
    verdicts = lines[1:-1]
    if [v["key"] for v in verdicts] != list(range(len(units.units))):
        raise HarnessError("worker verdicts are out of order")
    modules = lines[-1]["module_sha256"]
    header = {
        "defaults": lines[0]["header"],
        "environment": lines[0]["environment"],
        "modules_checked": len(modules),
        "modules_sha256": modules,
        "worker_wall_seconds": round(wall, 3),
    }
    return header, verdicts


def _wait(
    proc: subprocess.Popen[bytes], timeout: float, stdout_fd: int, limit: int, stderr_fd: int
) -> int:
    """Wait for the worker, refusing it once its verdict or stderr file passes its cap."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(proc.args, timeout)
        try:
            returncode = proc.wait(timeout=min(_POLL_SECONDS, remaining))
        except subprocess.TimeoutExpired:
            returncode = None
        if os.fstat(stdout_fd).st_size > limit:
            raise HarnessError("worker output is over its size limit")
        if os.fstat(stderr_fd).st_size > STDERR_LIMIT:
            raise HarnessError("worker stderr is over its size limit")
        if returncode is not None:
            return returncode


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    """SIGKILL the worker's process group; an empty or already-reaped group is gone already."""
    for _ in range(2):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            break
        except ProcessLookupError:  # nothing left in the group
            break
        except PermissionError:  # macOS, on an exited but unreaped leader: reap it, then retry
            proc.wait()
    proc.wait()


def _timeout(text: str) -> float:
    """A finite, positive number of seconds."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("the worker timeout must be finite and positive")
    return value


def _output_limit(n_units: int) -> int:
    """Bytes the verdict stream may hold: a fixed allowance plus one short line per unit."""
    return 4_000_000 + 200 * n_units


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


def _pin_differences(by_pin: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, int]]:
    """Per predictor, the units whose verdict differs between the first pin and each other."""
    first = next(iter(by_pin))
    return {
        f"{first} vs {name}": {
            p: sum(a[p] != b[p] for a, b in zip(by_pin[first], v, strict=True)) for p in PREDICTORS
        }
        for name, v in by_pin.items()
        if name != first
    }


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return sha256(text.encode())


def _not_evaluated(summary: dict[str, Any], path: Path, reason: str) -> int:
    """Write the protocol section 10 summary and return exit code 3."""
    summary |= {"status": "not_evaluated", "reason": reason}
    digest = _write(path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    bench = summary["benchmark"]
    print(json.dumps({"benchmark": bench, "status": "not_evaluated", "summary_sha256": digest}))
    return 3


def run(args: argparse.Namespace, removed: int) -> int:
    for path in (args.data, args.out):
        if path.resolve().is_relative_to(WORKER.parent):
            raise HarnessError("data and output must sit apart from the harness folder")
        require_outside_or_ignored(HARNESS_ROOT, path)
        require_outside_or_ignored(args.ziran_repo, path)
    harness = isolation.harness_record(HARNESS_ROOT, args.practice)
    if args.expect_harness is not None and not (
        len(args.expect_harness) >= 7 and harness["commit"].startswith(args.expect_harness)
    ):  # operator error, nothing parsed yet: a refusal, not a section 10 report
        raise HarnessError("the harness commit differs from --expect-harness")
    isolation.require_full_clone(args.ziran_repo)
    pins = _pins(args.ziran_repo, args.pin)
    bench = args.benchmark
    summary_path = args.out / f"{bench}.summary.json"
    if summary_path.exists():  # one run per pin; a second run is a recorded deviation
        raise HarnessError(f"{args.out.name} already holds a {bench} summary")
    args.out.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "benchmark": bench,
        "protocol": PROTOCOL,
        "harness": harness,
        "environment_variables_removed": removed,
        "pins": {name: {"sha": sha} for name, sha in pins.items()},
        "primary": PRIMARY[bench],
        "run_settings": {
            "worker_timeout_seconds": args.worker_timeout,
            "expect_split": args.expect_split,
            "expect_harness": args.expect_harness,
        },
    }
    phase = "manifest"
    try:
        if args.manifest.is_file():
            summary["manifest_sha256"] = sha256(args.manifest.read_bytes())
        manifest = read_manifest(args.manifest)
        phase = "collect"
        units = collect(bench, args.data, manifest)
        if args.expect_split is not None and units.counts["split"] != args.expect_split:
            raise IntakeError(
                f"split holds {units.counts['split']} units, not --expect-split {args.expect_split}"
            )
    except IntakeError as exc:
        return _not_evaluated(summary, summary_path, str(exc))
    except Exception as exc:  # fail closed: the type only, never the message or any input
        return _not_evaluated(summary, summary_path, f"{phase}: {type(exc).__name__}")
    summary["intake"] = {
        "counts": units.counts,
        "spdx": units.spdx,
        "terms_spdx": units.terms_spdx,
        "manifest_files": units.manifest_files,
        "extra_sha256": units.extra_hashes,
    }
    rows: list[str] = []
    by_pin: dict[str, list[dict[str, Any]]] = {}
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
            header, verdicts = _worker(export.resolve(), cwd, units, args.worker_timeout)
        summary["pins"][name] |= header
        by_pin[name] = verdicts
        summary["metrics"][name] = _metrics(units, verdicts)
        summary["bootstrap"][name] = _bootstrap(units, verdicts, PRIMARY[bench])
        for u, v in zip(units.units, verdicts, strict=True):
            row = {
                "benchmark": bench, "pin": name, "unit_id": u.unit_id, "variant": u.variant,
                "label": u.label, "excluded": u.excluded, "cells": u.cells,
                **{p: bool(v[p]) for p in PREDICTORS},
            }  # fmt: skip
            rows.append(json.dumps(row, sort_keys=True) + "\n")
    summary["pin_differences"] = _pin_differences(by_pin)
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


def _exit_on_signal(signum: int, _frame: object) -> None:
    """Turn SIGTERM and SIGHUP into SystemExit, so the worker's group is killed on the way out."""
    sys.exit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _exit_on_signal)
    try:
        isolation.require_interpreter_flags()
        if any(name.split(".")[0] == "ziran" for name in sys.modules):
            raise HarnessError("ziran is loaded in the harness process; only workers load it")
        removed = isolation.scrub_environ(os.environ)
        block_network(processes=False)
        return run(_args(argv), removed)
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
