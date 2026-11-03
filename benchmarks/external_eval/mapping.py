"""Benchmark records to detector inputs and labels (protocol sections 2, 4, 5 and 7).

Each function turns one parsed record into one :class:`Unit` per row variant. A unit holds the
response text only in memory, to send to the worker; the rows the harness writes keep the id,
variant, cells, label and verdicts and nothing else.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from benchmarks.external_eval.injecagent_eval import evaluate_output_prompted, prompted_text
from benchmarks.external_eval.intake import IntakeError, require_fields

#: The marker that opens ImportantInstructionsAttack._JB_STRING (protocol section 7).
MARKER = "<INFORMATION>"

_AGENTDOJO_PATH = re.compile(
    r"^runs/(?P<model>[^/]+)/(?P<suite>[^/]+)/(?P<user_task>[^/]+)"
    r"/important_instructions/(?P<injection_task>[^/]+)\.json$"
)
_AGENTDOJO_DEFENCE = re.compile(
    r"-(repeat_user_prompt|spotlighting_with_delimiting|tool_filter|transformers_pi_detector)$"
)
_AGENTDOJO_FIELDS = ("security", "error", "messages", "injections")

#: Member names come from the archive, so only a safe character set is admitted; the model
#: cell and unit id are taken from them.
_INJECAGENT_MEMBER = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)*prompted_(?P<model>[A-Za-z0-9_.-]+)_InjecAgent"
    r"/test_cases_(?P<case_type>dh|ds)_(?P<setting>base|enhanced)\.json"
)
_VERSION = re.compile(r"v?[0-9]+(?:\.[0-9]+)*")
_INJECAGENT_FIELDS = (
    "output",
    "User Instruction",
    "Attacker Tools",
    "User Tool",
    "Attacker Instruction",
)
_SKIPPED_ACTIONS = ("None", "N/A")

JAILBREAKBENCH_FIELDS = ("goal", "prompt", "target_response", "human_majority")
_HARMBENCH_FIELDS = ("test_case", "generation", "model", "human_0", "human_1", "human_2")


class Unit(BaseModel):
    """One response with one label, in one row variant."""

    benchmark: str
    unit_id: str
    variant: str
    prompt: str
    content: str
    tool_calls: list[dict[str, Any]]
    label: bool | None
    excluded: str | None
    cluster: str
    cells: dict[str, str]
    notes: tuple[str, ...] = ()


# ── AgentDojo ─────────────────────────────────────────────────────────


def agentdojo_admitted(rel: str) -> bool:
    """A log in the split: attack important_instructions, an undefended model folder."""
    m = _AGENTDOJO_PATH.match(rel)
    if m is None:
        return False
    model = m["model"]
    return model != "Meta-SecAlign-70B" and _AGENTDOJO_DEFENCE.search(model) is None


def _text(content: object) -> str | None:
    """A message's text: a string as is, the ``content`` of its text blocks, or None."""
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            str(b.get("content") or "")
            for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        ]
        return "\n".join(parts) if parts else None
    raise IntakeError(f"message content is a {type(content).__name__}")


def _assistant_view(messages: list[Any]) -> tuple[str, list[dict[str, Any]]]:
    texts: list[str] = []
    calls: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        text = _text(msg.get("content"))
        if text is not None:
            texts.append(text)
        raw = msg.get("tool_calls") or []
        if not isinstance(raw, list):
            raise IntakeError("assistant tool calls are not a list of tool call objects")
        for call in raw:
            if not isinstance(call, dict) or not isinstance(call.get("function"), str):
                raise IntakeError("assistant tool call has no function name")
            calls.append({"name": call["function"], "arguments": call.get("args")})
    return "\n".join(texts), calls


def agentdojo_units(rel: str, log: object) -> list[Unit]:
    """Whole-trace, post-injection and text-only units for one run log."""
    m = _AGENTDOJO_PATH.match(rel)
    if m is None:
        raise IntakeError(f"{rel}: not an AgentDojo run log path")
    require_fields(log, _AGENTDOJO_FIELDS, rel)
    assert isinstance(log, dict)
    messages = log["messages"]
    if not isinstance(messages, list) or not all(isinstance(x, dict) for x in messages):
        raise IntakeError(f"{rel}: messages is not a list of objects")
    if log["error"] is None and not isinstance(log["security"], bool):
        raise IntakeError(f"{rel}: security is not a boolean")

    user = next((x for x in messages if x.get("role") == "user"), None)
    prompt = (_text(user.get("content")) if user else None) or ""
    content, calls = _assistant_view(messages)
    cut = next(
        (
            i
            for i, x in enumerate(messages)
            if x.get("role") == "tool" and MARKER in (_text(x.get("content")) or "")
        ),
        None,
    )
    post_content, post_calls = _assistant_view(messages[cut + 1 :]) if cut is not None else ("", [])

    excluded = None if log["error"] is None else "error"
    version = log.get("benchmark_version")
    base: dict[str, Any] = {
        "benchmark": "agentdojo",
        "unit_id": rel,
        "prompt": prompt,
        "label": None if excluded else log["security"],
        "excluded": excluded,
        "cluster": f"{m['suite']}/{m['user_task']}/{m['injection_task']}",
        "cells": {
            "model": m["model"],
            "suite": m["suite"],
            "suite_version": "unrecorded"
            if version is None
            else version
            if isinstance(version, str) and _VERSION.fullmatch(version)
            else "unrecognised",
        },
    }
    return [
        Unit(**base, variant="whole", content=content, tool_calls=calls),
        Unit(
            **base,
            variant="post_injection",
            content=post_content,
            tool_calls=post_calls,
            notes=() if cut is not None else ("no_marker",),
        ),
        Unit(**base, variant="text_only", content=content, tool_calls=[]),
    ]


# ── InjecAgent ────────────────────────────────────────────────────────


def injecagent_member(name: str) -> tuple[str, str, str] | None:
    """(model, case type, setting) for a step-1 output file of a prompted agent, else None."""
    m = _INJECAGENT_MEMBER.fullmatch(name)
    return (m["model"], m["case_type"], m["setting"]) if m else None


def injecagent_units(
    member: str, line_no: int, item: object, where: str | None = None
) -> list[Unit]:
    """Whole and text-only units for one output, labelled by the pinned evaluator's copy.

    ``where`` names the unit in error messages; the caller passes the member index.
    """
    unit_id = f"{member}:{line_no}"
    where = where or unit_id
    parsed = injecagent_member(member)
    if parsed is None:
        raise IntakeError(f"{where}: not a prompted InjecAgent output file")
    require_fields(item, _INJECAGENT_FIELDS, where)
    assert isinstance(item, dict)
    tools = item["Attacker Tools"]
    if not isinstance(tools, list) or not tools:
        raise IntakeError(f"{where}: Attacker Tools is not a non-empty list")
    output = item["output"]

    notes: list[str] = []
    try:
        result = evaluate_output_prompted(
            output, tools[0], tools, item["User Tool"], item["Attacker Instruction"]
        )
    except Exception:
        result = None
    calls: list[dict[str, Any]] = []
    if result is None:
        label, excluded = None, "parse_error"
    elif result["eval"] == "invalid":
        label, excluded = None, "invalid"
        notes.append(str(result.get("invalid_reason")))
    else:
        label, excluded = result["eval"] == "succ", None
        calls = [
            {"name": value}
            for key, value in result["info_list"]
            if key == "Action" and value not in _SKIPPED_ACTIONS
        ]
    if result is not None and "eval" in item and item["eval"] != result["eval"]:
        notes.append("shipped_eval_differs")

    model, case_type, setting = parsed
    base: dict[str, Any] = {
        "benchmark": "injecagent",
        "unit_id": unit_id,
        "prompt": str(item["User Instruction"]),
        "content": prompted_text(output) if isinstance(output, str) else "",
        "label": label,
        "excluded": excluded,
        "cluster": json.dumps([item["User Instruction"], item["Attacker Instruction"]]),
        "cells": {"model": model, "case_type": case_type, "setting": setting},
        "notes": tuple(notes),
    }
    return [
        Unit(**base, variant="whole", tool_calls=calls),
        Unit(**base, variant="text_only", tool_calls=[]),
    ]


# ── JailbreakBench and HarmBench ──────────────────────────────────────


def jailbreakbench_unit(index: int, row: dict[str, str]) -> Unit:
    """One row of judge-comparison.csv; ``human_majority`` other than 0 or 1 is excluded."""
    require_fields(row, JAILBREAKBENCH_FIELDS, f"row {index}")
    raw = row["human_majority"]
    label = {"0": False, "1": True}.get(raw.strip() if isinstance(raw, str) else "")
    return Unit(
        benchmark="jailbreakbench",
        unit_id=f"row:{index}",
        variant="whole",
        prompt=row["prompt"],
        content=row["target_response"],
        tool_calls=[],
        label=label,
        excluded=None if label is not None else "label_not_binary",
        cluster=row["goal"],
        cells={},
    )


def harmbench_units(data: object) -> list[Unit]:
    """Items of the text validation set; positive when at least two human labels are 1."""
    if not isinstance(data, dict):
        raise IntakeError("validation set is not an object of behaviour ids")
    units: list[Unit] = []
    for b, (behaviour, items) in enumerate(data.items()):
        if not isinstance(items, list):
            raise IntakeError(f"behaviour {b}: items are not a list")
        for i, item in enumerate(items):
            require_fields(item, _HARMBENCH_FIELDS, f"behaviour {b} item {i}")
            votes = [item[f"human_{j}"] for j in range(3)]
            binary = all(type(v) is int and v in (0, 1) for v in votes)
            model = str(item["model"])
            units.append(
                Unit(
                    benchmark="harmbench",
                    unit_id=f"{behaviour}:{i}",
                    variant="whole",
                    prompt=str(item["test_case"]),
                    content=str(item["generation"]),
                    tool_calls=[],
                    label=sum(votes) >= 2 if binary else None,
                    excluded=None if binary else "label_not_binary",
                    cluster=str(behaviour),
                    cells={"model": "unnamed" if model == ".json" else model},
                )
            )
    return units
