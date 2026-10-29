"""Score units with one pinned ziran export (protocol section 4, run conditions).

Run as ``python -I worker.py <export>``. It imports only the standard library and the export,
which goes first on ``sys.path``. It reads units as JSON lines on stdin (key, prompt, content,
tool_calls) and writes JSON lines on stdout: a header with the pin's defaults, one verdict per
unit, and an end line. Logging goes to stderr, which the harness keeps and never prints.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import Any

#: Audit events that reach the network; any of them raises (protocol section 9).
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


def block_sockets() -> None:
    """Refuse every network call for the rest of the process (audit hooks cannot be removed)."""

    def hook(event: str, _args: tuple[Any, ...]) -> None:
        if event in _NETWORK_EVENTS:
            raise RuntimeError(f"{event} is blocked")

    sys.addaudithook(hook)


def check_loaded_modules(root: Path) -> int:
    """Count the loaded ziran modules; refuse if any resolves outside the export."""
    count = 0
    for name, module in list(sys.modules.items()):
        if name.split(".")[0] != "ziran":
            continue
        file = getattr(module, "__file__", None)
        locations = [file] if file else list(getattr(module, "__path__", []))
        for loc in locations:
            if not Path(loc).resolve().is_relative_to(root):
                raise SystemExit(f"{name} resolves outside the export")
        count += 1
    return count


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
    out.write(json.dumps({"header": defaults, "modules": check_loaded_modules(root)}) + "\n")
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
    block_sockets()
    out = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8")
    sys.stdout = sys.stderr  # nothing the export prints can reach the verdict stream
    sys.path.insert(0, str(root))
    n = asyncio.run(_score(sys.stdin, out, root))
    out.write(json.dumps({"end": n, "modules": check_loaded_modules(root)}) + "\n")
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
