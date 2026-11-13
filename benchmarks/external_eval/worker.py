"""Score units with one pinned ziran export (protocol section 4, run conditions).

Run as ``python -I worker.py <export> [replies|record_to <path> <model> <client version>]``. It
imports only the standard library and the export, which goes first on ``sys.path``. It reads
units as JSON lines on stdin (key, prompt, content, tool_calls, the keys of :data:`METADATA_KEYS`
and, on an AgentDojo unit, ``judge``: its variant and unit id) and writes JSON lines on
stdout: a header with the pin's defaults, one verdict per unit, and an end line. Logging goes to
stderr, which the harness keeps and never prints.

With the hybrid arguments, at a pin that ships ``ziran.application.hybrid.jobs`` (spec 067),
the trace judge runs on each AgentDojo variant at share 1.0 through the record-and-replay client:
``replies`` reads hybrid_send's ``outcomes.jsonl``, ``record_to`` writes the requests and scores
nothing. ``hybrid`` is the judge's verdict, and ``hybrid_r025`` to ``hybrid_r075`` the same
replies for the units ``routed(band, s)`` sends at 0.25, 0.5 and 0.75, the first pass for the
rest (spec 070). The end line counts, per variant, the band, the units each share sends, the
outcomes and the renders the mask changes; no text.

``deterministic`` is ``provenance(...).hit`` at a pin that ships
``ziran.application.detectors.provenance`` (spec 063), and null at one that does not. A unit on
which the pin raises ``ProvenanceInputError`` gets ``{"key": k, "raised": true}`` and no verdict;
the harness excludes it (spec 065). Any other exception stops the worker.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import importlib.util
import json
import os
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

#: Audit events that reach the network (protocol section 9).
_NETWORK_EVENTS = frozenset(
    {
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.getnameinfo",
        "socket.sendmsg",
        "socket.sendto",
    }
)
#: Events that start a process or load a C library, which would bypass the hook.
_PROCESS_EVENTS = frozenset(
    {
        "ctypes.dlopen",
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.spawn",
        "os.system",
        "subprocess.Popen",
    }
)
#: The keys passed in ``AgentResponse.metadata``, and nothing else: the detector's (patch
#: protocol 5), then the two only the trace judge reads (spec 067), which no detector reads.
METADATA_KEYS = ("trusted_task", "tool_results", "payload", "user_messages", "final_answer")
#: The routing-share rows read from the replies at share 1.0 (patch protocol section 6).
SHARES = {"hybrid_r025": 0.25, "hybrid_r050": 0.5, "hybrid_r075": 0.75}


def block_network(*, processes: bool = True) -> None:
    """Refuse network calls, and by default new processes and C libraries, from now on.

    Audit hooks cannot be removed. The worker blocks both; the harness process blocks the
    network only, since it starts git and its workers itself.
    """
    blocked = _NETWORK_EVENTS | (_PROCESS_EVENTS if processes else frozenset())

    def hook(event: str, _args: tuple[Any, ...]) -> None:
        if event in blocked:
            raise RuntimeError(f"{event} is blocked")

    sys.addaudithook(hook)


def check_loaded_modules(root: Path) -> dict[str, str]:
    """sha256 of each loaded ziran module file; refuse if any resolves outside the export."""
    hashes: dict[str, str] = {}
    for name, module in sorted(sys.modules.items()):
        if name.split(".")[0] != "ziran":
            continue
        file = getattr(module, "__file__", None)
        locations = [file] if file else list(getattr(module, "__path__", []))
        for loc in locations:
            if not Path(loc).resolve().is_relative_to(root):
                raise SystemExit(f"{name} resolves outside the export")
        if file:
            path = Path(file).resolve()
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return hashes


def installed_sha256() -> str:
    """sha256 of the sorted ``name==version`` lines of the running environment."""
    lines = sorted(
        f"{(d.metadata['Name'] or '').lower()}=={d.version}" for d in metadata.distributions()
    )
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def _environment() -> dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "installed_sha256": installed_sha256(),
        "variables": sorted(os.environ),  # names only, to show the allow-list held
    }


def _jsonable(value: object) -> object:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return sorted(value)  # client mappings: names only
    return value


def _mask_changed(jobs: Any, prompt: Any, response: Any) -> bool:
    """Whether the mask changes this request: the render with the mask off differs."""
    masked, mask = jobs.render_trace(prompt, response), jobs.mask
    jobs.mask = str  # the identity on text; restored before any other render
    try:
        return bool(jobs.render_trace(prompt, response) != masked)
    finally:
        jobs.mask = mask


async def _judge(
    jobs: Any, routed: Any, client: Any, judged: dict[str, dict[str, Any]], rows: list[Any]
) -> dict[str, dict[str, Any]]:
    """Add the hybrid verdicts to ``rows``; return each variant's counts."""
    prompt = jobs.load("trace_judge", jobs.TRACE_JUDGE_VERSION)
    counts: dict[str, dict[str, Any]] = {}
    for variant, group in sorted(judged.items()):
        traces = {u: (response, prov) for u, (_, response, prov) in group.items()}
        result = await jobs.judge_traces(traces, client, share=1.0)
        band = result.sent  # at 1.0 every band unit is sent
        sent = {name: set(routed(band, share)) for name, share in SHARES.items()}
        outcomes: dict[str, int] = {}
        for u, (key, _, prov) in group.items():
            row = rows[key]
            row["hybrid"] = result.verdicts[u].success
            for name, units in sent.items():
                row[name] = row["hybrid"] if u in units else prov.hit
            if u in band:
                row["llm"] = result.llm_pending.get(u, "reply")
                outcomes[row["llm"]] = outcomes.get(row["llm"], 0) + 1
        counts[variant] = {
            "band": len(band),
            "sent": {name: len(units) for name, units in sent.items()},
            "outcomes": outcomes,
            "mask_changed": sum(_mask_changed(jobs, prompt, traces[u][0]) for u in band),
        }
    return counts


async def _score(lines: Any, out: Any, root: Path, hybrid: list[str]) -> tuple[int, Any]:
    from ziran.application.detectors.pipeline import DetectorConfig, DetectorPipeline
    from ziran.application.detectors.thresholds import DetectorThresholds
    from ziran.domain.entities.attack import AttackPrompt
    from ziran.domain.interfaces.adapter import AgentResponse

    config = DetectorConfig()
    thresholds = DetectorThresholds()
    defaults = {
        "thresholds": thresholds.model_dump(mode="json"),
        "config": {f.name: _jsonable(getattr(config, f.name)) for f in dataclasses.fields(config)},
    }
    pipeline = DetectorPipeline(detector_config=config)
    first_pass = None  # a pin from before spec 063 has no module: no deterministic row
    if importlib.util.find_spec("ziran.application.detectors.provenance") is not None:
        from ziran.application.detectors import provenance as first_pass  # a broken one stops
    jobs = client = routed = None
    if (
        hybrid
        and first_pass is not None
        and importlib.util.find_spec("ziran.application.hybrid") is not None
        and importlib.util.find_spec("ziran.application.hybrid.jobs") is not None
    ):
        from ziran.application.hybrid import jobs, routed
        from ziran.infrastructure.llm.replay_client import RecordReplayClient

        mode, path, model, version = hybrid
        client = RecordReplayClient(model, version, **{mode: Path(path)})
    check_loaded_modules(root)
    out.write(json.dumps({"header": defaults, "environment": _environment()}) + "\n")
    hit = thresholds.hit
    rows: list[dict[str, Any]] = []
    judged: dict[str, dict[str, Any]] = {}
    for line in lines:
        unit = json.loads(line)
        prompt = unit["prompt"]
        response = AgentResponse(
            content=unit["content"],
            tool_calls=unit["tool_calls"],
            metadata={k: unit[k] for k in METADATA_KEYS if k in unit},
        )
        spec = AttackPrompt(template=prompt, success_indicators=[], failure_indicators=[])
        try:
            verdict = await pipeline.evaluate(prompt, response, spec, None)
            prov = first_pass.provenance(prompt, response, None) if first_pass else None
        except ValueError as exc:
            if first_pass is None or not isinstance(exc, first_pass.ProvenanceInputError):
                raise
            rows.append({"key": unit["key"], "raised": True})
            continue
        scores = {r.detector_name: r.score for r in verdict.detector_results}
        rows.append(
            {
                "key": unit["key"],
                "refusal": scores["refusal"] >= hit,
                "side_effect": scores["side_effect"] >= hit,
                "pipeline": verdict.successful,
                "deterministic": prov.hit if prov else None,
            }
        )
        if jobs is not None and "judge" in unit:
            variant, unit_id = unit["judge"]
            judged.setdefault(variant, {})[unit_id] = (unit["key"], response, prov)
    counts = await _judge(jobs, routed, client, judged, rows) if jobs is not None else None
    for row in rows:
        out.write(json.dumps(row) + "\n")
    return len(rows), counts


def main(argv: list[str]) -> int:
    if not sys.flags.isolated or sys.flags.optimize:
        raise SystemExit("run the worker with python -I and without -O")
    root = Path(argv[1]).resolve()
    block_network()
    out = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8")
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())  # nothing the export writes reaches it
    sys.stdout = sys.stderr
    sys.path.insert(0, str(root))
    n, hybrid = asyncio.run(_score(sys.stdin, out, root, argv[2:]))
    end = {"end": n, "module_sha256": check_loaded_modules(root), "hybrid": hybrid}
    out.write(json.dumps(end) + "\n")
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
