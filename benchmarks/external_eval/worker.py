"""Score units with one pinned ziran export (protocol section 4, run conditions).

Run as ``python -I worker.py <export>``. It imports only the standard library and the export,
which goes first on ``sys.path``. It reads units as JSON lines on stdin (key, prompt, content,
tool_calls) and writes JSON lines on stdout: a header with the pin's defaults, one verdict per
unit, and an end line. Logging goes to stderr, which the harness keeps and never prints.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
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


def _environment() -> dict[str, str]:
    lines = sorted(
        f"{(d.metadata['Name'] or '').lower()}=={d.version}" for d in metadata.distributions()
    )
    return {
        "python": sys.version.split()[0],
        "installed_sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
    }


def _jsonable(value: object) -> object:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return sorted(value)  # client mappings: names only
    return value


async def _score(lines: Any, out: Any, root: Path) -> int:
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
    check_loaded_modules(root)
    out.write(json.dumps({"header": defaults, "environment": _environment()}) + "\n")
    hit = thresholds.hit
    n = 0
    for line in lines:
        unit = json.loads(line)
        prompt = unit["prompt"]
        response = AgentResponse(content=unit["content"], tool_calls=unit["tool_calls"])
        spec = AttackPrompt(template=prompt, success_indicators=[], failure_indicators=[])
        verdict = await pipeline.evaluate(prompt, response, spec, None)
        scores = {r.detector_name: r.score for r in verdict.detector_results}
        out.write(
            json.dumps(
                {
                    "key": unit["key"],
                    "refusal": scores["refusal"] >= hit,
                    "side_effect": scores["side_effect"] >= hit,
                    "pipeline": verdict.successful,
                }
            )
            + "\n"
        )
        n += 1
    return n


def main(argv: list[str]) -> int:
    if not sys.flags.isolated or sys.flags.optimize:
        raise SystemExit("run the worker with python -I and without -O")
    root = Path(argv[1]).resolve()
    block_network()
    out = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8")
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())  # nothing the export writes reaches it
    sys.stdout = sys.stderr
    sys.path.insert(0, str(root))
    n = asyncio.run(_score(sys.stdin, out, root))
    out.write(json.dumps({"end": n, "module_sha256": check_loaded_modules(root)}) + "\n")
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
