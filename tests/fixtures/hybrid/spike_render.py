"""Render AgentDojo logs with the spike's own renderer, for the trace judge's byte-equal tests.

Run from a git archive of taoq-ai/ziran-paper (never a live checkout), with ``python -I``:

    python -I spike_render.py <paper tree> <out.json> <log.json> [<log.json> ...]

Each log is rendered with ``g11_judge_spike.render_trace``, its call evidence from
``g11_dev_sets.calls_view``, after prompt v1 as the spike's ``request_rows`` joins them. The out
file lists ``{name, log, response, request_text}``; ``response`` is the log as ziran's
``AgentResponse``, with the section 5 keys and the judge's (``user_messages``, ``final_answer``,
a call's ``id``, a result's ``tool_call_id`` and ``name``). The ``request_text`` of
``trace_judge_spike_render.json`` and ``trace_judge_spike_render_error.json``, whose responses
hold the section 5 keys only, is this script's for their ``log``.
"""

import json
import sys
from pathlib import Path


def response(log: dict) -> dict:
    messages = log.get("messages") or []
    calls, results = [], []
    for i, m in enumerate(messages):
        if m.get("role") == "assistant":
            for c in m.get("tool_calls") or []:
                calls.append(
                    {
                        "id": c.get("id"),
                        "name": c["function"],
                        "arguments": c.get("args"),
                        "message_index": i,
                    }
                )
        elif m.get("role") == "tool":
            r = {
                "message_index": i,
                "text": m.get("content") or "",
                "tool_call_id": m.get("tool_call_id"),
                "name": (m.get("tool_call") or {}).get("function"),
            }
            if m.get("error"):
                r["error"] = str(m["error"])
            results.append(r)
    users = [m.get("content") or "" for m in messages if m.get("role") == "user"]
    last = messages[-1] if messages else {}
    final = (
        (last.get("content") or "")
        if last.get("role") == "assistant" and not last.get("tool_calls")
        else ""
    )
    meta = {
        "tool_results": results,
        "payload": list((log.get("injections") or {}).values()),
        "user_messages": users,
        "final_answer": final,
    }
    if users:
        meta["trusted_task"] = users[0]
    return {"content": "", "tool_calls": calls, "metadata": meta}


def main(paper: Path, out: Path, logs: list[Path]) -> None:
    sys.path.insert(0, str(paper / "study" / "scripts"))
    import g11_judge_spike as js  # the paper tree is known only at run time

    head = (
        (paper / "specs" / "035-g11-judge-spike" / "prompt-v1.md")
        .read_bytes()
        .decode()
        .rstrip("\n")
    )
    cases = []
    for path in logs:
        log = json.loads(path.read_text())
        view = js.ds.calls_view(js.gp.trace_of(log), lambda name: False)
        text = head + "\n\n" + js.render_trace(log, view)
        cases.append(
            {"name": path.stem, "log": log, "response": response(log), "request_text": text}
        )
    out.write_text(json.dumps(cases, ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), [Path(p) for p in sys.argv[3:]])
