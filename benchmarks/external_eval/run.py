"""External detection evaluation harness (spec 062; ziran-paper prereg/ext-eval-protocol.md).

Scores ziran's response detectors on one benchmark against the benchmark's own labels, at each
ziran pin, in a fresh worker process per pin. Writes only counts, hashes, unit ids, labels and
verdicts: ``<out>/<benchmark>.rows.jsonl`` and ``<out>/<benchmark>.summary.json``. Each row is
one unit, its keys and value types held to ziran-paper ``prereg/patch-protocol.md`` section 8
(:func:`check_row`); a row outside them stops the run with nothing written.

A unit on which a pin's detector raises ``ProvenanceInputError`` is excluded as
``detector_raised`` at every pin, whatever its label (spec 065), and counted per pin.

Usage (from any folder; ``-I`` is required)::

    uv run --frozen python -I benchmarks/external_eval/run.py --benchmark agentdojo \\
        --data <intake folder> --manifest <manifest.json> --ziran-repo <ziran clone> \\
        --pin study-v1=<sha> --pin study-v0=b813e4f --out <git-ignored folder>

The fresh and reserve AgentDojo sets (``agentdojo_fresh``, ``agentdojo_reserve``) also need
``--paper <ziran-paper checkout>``: the run refuses before it opens ``--data`` unless that
checkout's run guard admitted it (:func:`require_admitted`, spec 069). Reserve rows carry an
``attack`` cell beside the model folder.

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
import re  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from collections import defaultdict  # noqa: E402
from typing import Any  # noqa: E402

from benchmarks.external_eval import isolation, mapping, metrics  # noqa: E402
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
#: ``hybrid`` is the trace judge at ``hybrid_route_share`` 1.0; ``hybrid_r025`` to ``_r075`` read
#: the same replies at 0.25, 0.5 and 0.75 (patch protocol section 6, routing share; spec 070).
PREDICTORS = ("refusal", "side_effect", "pipeline", "deterministic", "hybrid", "hybrid_r025",
              "hybrid_r050", "hybrid_r075")  # fmt: skip
#: The trace judge's variants: the payload-known row (patch protocol, deviation of 2026-11-12).
JUDGED = frozenset({"payload_whole", "payload_post_injection"})
#: Patch protocol section 8: the only keys a row holds, and their value rules.
ROW_KEYS = frozenset(
    {"benchmark", "unit_id", "variant", "cluster", "cells", "label", "excluded", "notes",
     "verdicts", "reply_outcome"}
)  # fmt: skip
REPLY_OUTCOMES = frozenset(
    {"reply", "unparsed", "no_text", "not_sent_oversize", "step_stopped", "no_reply_at_bound",
     "scan_hit"}
)  # fmt: skip
NOTES = frozenset({"no_marker", "shipped_eval_differs"}) | mapping.INVALID_REASONS
EXCLUDED = frozenset({"error", "parse_error", "invalid", "label_not_binary", "detector_raised"})
VARIANTS = frozenset(
    {"whole", "post_injection", "text_only", "payload_whole", "payload_post_injection"}
)
_ID = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")  # a sha256 is an id too
_UNIT_ID = re.compile(r"[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*")  # "member:line", "row:3"
_PIN_NAME = re.compile(r"[A-Za-z0-9_.-]+")
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
#: Patch protocol section 16, the run guards: each guarded set's use log in ziran-paper, which
#: ``study/scripts/g11_run_guard.py`` (G11-RUN-GUARDS) writes before the set is fetched.
USE_LOGS = {
    "agentdojo_fresh": "study/results/g11_fresh_uses.jsonl",
    "agentdojo_reserve": "study/results/g11_reserve_uses.jsonl",
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
    p.add_argument("--paper", type=Path, help="ziran-paper checkout whose run guard admitted a "
                   "fresh or reserve run (required for those sets)")  # fmt: skip
    p.add_argument("--expect-split", type=int, help="split count from the intake addendum")
    p.add_argument("--expect-harness", help="harness commit from the intake addendum")
    p.add_argument(
        "--worker-timeout", type=_timeout, default=WORKER_TIMEOUT, help="seconds per pin worker"
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--hybrid-replies", type=Path, help="hybrid_send's outcomes.jsonl")
    mode.add_argument("--hybrid-record", type=Path, help="request file to write; scores nothing")
    p.add_argument("--hybrid-model", help="the trace judge's model id, part of each request key")
    p.add_argument("--hybrid-client-version", help="the model client's version, part of each key")
    args = p.parse_args(argv)
    path = args.hybrid_replies or args.hybrid_record
    if (path is None) != (args.hybrid_model is None) or (path is None) != (
        args.hybrid_client_version is None
    ):
        p.error("--hybrid-replies or --hybrid-record goes with --hybrid-model and "
                "--hybrid-client-version")  # fmt: skip
    if args.hybrid_record is not None and not args.hybrid_record.name.endswith(".requests.jsonl"):
        p.error("a --hybrid-record file's name ends in .requests.jsonl")
    return args


def _hybrid_argv(args: argparse.Namespace) -> list[str]:
    """The worker's hybrid arguments: the client's keyword, its path, the model, the version."""
    if args.hybrid_replies is not None:
        return ["replies", str(args.hybrid_replies.resolve()), args.hybrid_model,
                args.hybrid_client_version]  # fmt: skip
    if args.hybrid_record is not None:
        return ["record_to", str(args.hybrid_record.resolve()), args.hybrid_model,
                args.hybrid_client_version]  # fmt: skip
    return []


def _pins(repo: Path, specs: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for spec in specs:
        name, sep, rev = spec.partition("=")
        if not sep or not _PIN_NAME.fullmatch(name) or not rev or name in pins:
            raise HarnessError(f"--pin {spec!r} is not a new NAME=REV")
        pins[name] = isolation.resolve_sha(repo, rev)
    return pins


class WorkerTimeoutError(HarnessError):
    """A worker that runs past ``--worker-timeout``; the run stops with exit 2."""


def _worker(
    export: Path, cwd: Path, units: Collected, timeout: float, hybrid: list[str] | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run one fresh worker on every unit; its stderr is kept and never printed.

    stdin, stdout and stderr are temporary files, not pipes, so neither side can block on a
    full pipe and the timeout waits on the process alone. The worker's whole process group is
    killed on every way out of the wait: a timeout (exit 2, no summary), Ctrl-C, SIGTERM or
    SIGHUP to the harness (``main`` turns the last two into ``SystemExit``), a verdict or stderr
    file past its cap, and normal exit. SIGKILL to the harness cannot be handled.
    """
    payload = "".join(
        json.dumps(_worker_unit(i, u)) + "\n" for i, u in enumerate(units.units)
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
            [sys.executable, "-I", str(WORKER), str(export), *(hybrid or [])],
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
        "hybrid": lines[-1].get("hybrid"),  # counts only, per judged variant; None: not judged
    }
    return header, verdicts


def _worker_unit(key: int, u: mapping.Unit) -> dict[str, Any]:
    """What the worker reads: the response, and the section 5 keys (no task when none is known)."""
    unit: dict[str, Any] = {
        "key": key, "prompt": u.prompt, "content": u.content, "tool_calls": u.tool_calls,
        "tool_results": u.tool_results, "payload": u.payload,
    }  # fmt: skip
    for name in ("trusted_task", "user_messages", "final_answer"):
        if getattr(u, name) is not None:
            unit[name] = getattr(u, name)
    if u.variant in JUDGED and u.excluded is None:  # an error log is never sent to the judge
        unit["judge"] = [u.variant, u.unit_id]
    return unit


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
        # the hybrid rows exist on the judged variants only
        in_variant = [v for u, v in zip(units.units, verdicts, strict=True) if u.variant == variant]
        for pred in _scored(in_variant):
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


def _scored(verdicts: list[dict[str, Any]]) -> list[str]:
    """The predictors this pin gives: a pin before spec 063 has no deterministic verdict."""
    return [p for p in PREDICTORS if any(v.get(p) is not None for v in verdicts)]


def _bootstrap(
    units: Collected, verdicts: list[dict[str, Any]], pred: str
) -> dict[str, Any] | None:
    if pred not in _scored(verdicts):
        return None
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
            p: sum(
                a.get(p) is not None and b.get(p) is not None and a[p] != b[p]
                for a, b in zip(by_pin[first], v, strict=True)
            )
            for p in _scored(by_pin[first])
            if p in _scored(v)
        }
        for name, v in by_pin.items()
        if name != first
    }


def _reply_outcome(causes: list[str | None]) -> str | None:
    """The sender's outcome class of a unit's judge request, from the first pin that sent it.

    A reply ziran's parse refused was still the sender's ``reply``; ``missing`` (no stored
    outcome) is no class, so null, and counted in the pin's ``hybrid`` outcomes.
    """
    cause = next((c for c in causes if c is not None), None)
    cause = "reply" if cause == "unusable_reply" else cause
    return cause if cause in REPLY_OUTCOMES else None


def _cluster_id(cluster: str) -> str:
    """The cluster as an id, or the sha256 of a cluster that holds record text."""
    return cluster if _ID.fullmatch(cluster) else sha256(cluster.encode())


def check_row(row: dict[str, Any]) -> None:
    """Refuse a row with any key or value outside patch protocol section 8.

    The message names the key that fails, never a value.
    """
    if set(row) != ROW_KEYS:
        raise HarnessError(f"row keys {sorted(set(row) ^ ROW_KEYS)} are outside the allowlist")
    verdicts, cells, notes = row["verdicts"], row["cells"], row["notes"]
    checks = {
        "benchmark": row["benchmark"] in PRIMARY,
        "unit_id": isinstance(row["unit_id"], str) and bool(_UNIT_ID.fullmatch(row["unit_id"])),
        "variant": row["variant"] in VARIANTS,
        "cluster": isinstance(row["cluster"], str) and bool(_ID.fullmatch(row["cluster"])),
        "cells": isinstance(cells, dict)
        and all(
            isinstance(v, str) and _ID.fullmatch(k) and _ID.fullmatch(v) for k, v in cells.items()
        ),
        "label": row["label"] is None or type(row["label"]) is bool,
        "excluded": row["excluded"] is None or row["excluded"] in EXCLUDED,
        "notes": isinstance(notes, list) and all(n in NOTES for n in notes),
        "verdicts": isinstance(verdicts, dict)
        and all(
            type(v) is bool
            and isinstance(k, str)
            and _PIN_NAME.fullmatch(k.partition("/")[0])
            and k.partition("/")[2] in PREDICTORS
            for k, v in verdicts.items()
        ),
        "reply_outcome": row["reply_outcome"] is None or row["reply_outcome"] in REPLY_OUTCOMES,
    }
    bad = sorted(k for k, ok in checks.items() if not ok)
    if bad:
        raise HarnessError(f"row values of {bad} are outside the allowlist")


def require_admitted(
    paper: Path | None, bench: str, manifest_path: Path, pins: dict[str, str]
) -> None:
    """Refuse a fresh or reserve run that the paper's guard has not admitted (section 16).

    ``g11_run_guard.guard`` commits an ``aborted`` line to the set's use log before the fetch,
    in the paper's main checkout on ``main``. The run goes on only when ``--paper`` is such a
    checkout's top level, the log is committed as it stands, holds no ``scored`` line, and its
    last line is ``aborted`` for one of the run's pins, at that pin's commit, and for the sorted
    run-log paths of the manifest. Nothing under ``--data`` is opened before this.
    """
    rel = USE_LOGS.get(bench)
    if rel is None:
        return
    if paper is None:
        raise HarnessError(f"{bench} needs --paper, the checkout whose run guard admitted it")
    if Path(isolation.git_text(paper, "rev-parse", "--show-toplevel")).resolve() != (
        paper.resolve()
    ):
        raise HarnessError("--paper is not the top level of a git checkout")
    try:
        branch = isolation.git_text(paper, "symbolic-ref", "--quiet", "HEAD")
    except HarnessError:  # a detached HEAD
        branch = None
    if branch != "refs/heads/main":
        raise HarnessError("--paper is not on main, where the guard runs")
    log = paper / rel
    if log.is_symlink() or not log.is_file():
        raise HarnessError(f"{log.name} is not a regular file in --paper")
    text = log.read_bytes()
    if text != isolation._git(paper, "show", f"HEAD:{rel}"):
        raise HarnessError(f"{log.name} is not committed as it stands")
    refused = HarnessError(f"a line of {log.name} is not a JSON object")
    try:
        lines = [json.loads(line) for line in text.splitlines() if line.strip()]
    except ValueError:
        raise refused from None
    if not all(isinstance(line, dict) for line in lines):
        raise refused
    if not lines:
        raise HarnessError(f"{log.name} holds no attempt")
    if any(line.get("status") == "scored" for line in lines):
        raise HarnessError(f"{log.name} holds a scored opening; the cap is 1")
    last = lines[-1]
    pin = last.get("pin")
    sha = pins.get(pin) if isinstance(pin, str) else None
    checks = {
        "status": last.get("status") == "aborted",
        "pin": sha is not None,
        "ziran_sha": sha is not None and last.get("ziran_sha") == sha,
    }
    bad = sorted(k for k, ok in checks.items() if not ok)
    if not bad:  # the manifest is opened only for a line that names this run
        run_logs = sorted(r for r in read_manifest(manifest_path).files if mapping.is_run_log(r))
        if last.get("sha256") != sha256("\n".join(run_logs).encode()):
            bad = ["sha256"]
    if bad:
        raise HarnessError(f"the last line of {log.name} does not admit this run: {bad}")


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
    hybrid_path = args.hybrid_replies or args.hybrid_record
    for path in (args.data, args.out, *([hybrid_path] if hybrid_path else [])):
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
    require_admitted(args.paper, bench, args.manifest, pins)
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
    if args.hybrid_replies is not None:
        summary["hybrid"] = {
            "model": args.hybrid_model,
            "client_version": args.hybrid_client_version,
            "replies_sha256": sha256(args.hybrid_replies.read_bytes()),
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
            header, verdicts = _worker(
                export.resolve(), cwd, units, args.worker_timeout, _hybrid_argv(args)
            )
        summary["pins"][name] |= header
        by_pin[name] = verdicts
    if hybrid_path is not None and all(summary["pins"][n]["hybrid"] is None for n in pins):
        raise HarnessError("no pin ships the hybrid trace judge")
    if args.hybrid_record is not None:  # nothing is scored from a record run
        hybrid = {name: summary["pins"][name]["hybrid"] for name in pins}
        print(json.dumps({"benchmark": bench, "status": "recorded", "hybrid": hybrid},
                         sort_keys=True))  # fmt: skip
        return 0
    # label-blind: a raise at any pin excludes the unit at every pin, so the pins stay paired
    raised = {i for v in by_pin.values() for i, x in enumerate(v) if x.get("raised")}
    # counted where the raise relabels the unit: a unit already excluded (error) keeps that
    summary["detector_raised"] = {
        name: sum(
            bool(x.get("raised")) and units.units[i].excluded is None for i, x in enumerate(v)
        )
        for name, v in by_pin.items()
    }
    units.units = [
        u.model_copy(update={"excluded": "detector_raised"})
        if i in raised and u.excluded is None
        else u
        for i, u in enumerate(units.units)
    ]
    for name, verdicts in by_pin.items():
        summary["metrics"][name] = _metrics(units, verdicts)
        summary["bootstrap"][name] = _bootstrap(units, verdicts, PRIMARY[bench])
    rows: list[str] = []
    for i, u in enumerate(units.units):
        row = {
            "benchmark": bench, "unit_id": u.unit_id, "variant": u.variant,
            "cluster": _cluster_id(u.cluster), "cells": u.cells, "label": u.label,
            "excluded": u.excluded, "notes": list(u.notes),
            "verdicts": {
                f"{name}/{p}": bool(v[i][p])
                for name, v in by_pin.items()
                for p in PREDICTORS
                if v[i].get(p) is not None
            },
            "reply_outcome": _reply_outcome([v[i].get("llm") for v in by_pin.values()]),
        }  # fmt: skip
        check_row(row)
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


#: The signals that end a run. Each unwinds through ``_worker``, which kills the worker's group,
#: and through the export folder's cleanup.
_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def _exit_on_signal(signum: int, _frame: object) -> None:
    """Ignore any repeat, then unwind: SIGINT as ``KeyboardInterrupt``, others as ``SystemExit``.

    ``uv run`` forwards a signal sent to the run's process group, so the harness gets it twice;
    a repeat raised inside the cleanup would skip the group kill or the export removal.
    """
    for s in _SIGNALS:
        signal.signal(s, signal.SIG_IGN)
    if signum == signal.SIGINT:
        raise KeyboardInterrupt
    sys.exit(128 + signum)


def _handle_signals() -> None:
    """Route ``_SIGNALS`` to ``_exit_on_signal``; one ignored at start (``nohup``) stays ignored."""
    for signum in _SIGNALS:
        if signal.getsignal(signum) != signal.SIG_IGN:
            signal.signal(signum, _exit_on_signal)


def main(argv: list[str] | None = None) -> int:
    _handle_signals()
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
