"""Dev replay on the iterate split (G10-HARNESS-FRESH): counts only, no record text.

Run after fetch_iterate.py and one harness run on its download, from the worktree root:

    uv run --frozen python -I benchmarks/external_eval/run.py --benchmark agentdojo \\
        --data "$DL/agentdojo" --manifest "$DL/iterate.manifest.json" --ziran-repo <ziran clone> \\
        --pin study-v1=study-v1 --pin patched=<commit> --out "$OUT" --expect-split 9912
    uv run --frozen python -I specs/065-harness-fresh/dev_replay.py <ziran-paper> "$DL" "$OUT" patched

1. study-v1 verdicts of the new mapping against the committed G-9 rows, unit by unit, on the
   iterate logs (variants whole, post_injection and text_only; refusal, side_effect, pipeline).
2. The patched pin's deterministic verdict against the frozen dev probe: T3 on `whole`, P1 on
   `payload_whole`, for every analysed iterate log.
"""

import importlib.util
import json
import lzma
import sys
from collections import Counter
from pathlib import Path

paper, dl, out, patched = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
scripts = paper / "study" / "scripts"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, scripts / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


probe = load("g10_dev_probe")
dev_sets = load("g11_dev_sets")

rows = [json.loads(x) for x in (out / "agentdojo.rows.jsonl").read_text().splitlines()]
ours = {(r["unit_id"], r["variant"]): r for r in rows}
iterate = {r["unit_id"] for r in rows}
dev_sets.guard(sorted(iterate), lockbox=False, who="G10-HARNESS-FRESH dev replay")

c: Counter[str] = Counter()
with lzma.open(paper / "study/results/ext-eval/agentdojo.rows.jsonl.xz", "rt") as fh:
    for line in fh:
        r = json.loads(line)
        if r["pin"] != "study-v1" or r["unit_id"] not in iterate:
            continue
        mine = ours[(r["unit_id"], r["variant"])]
        c["v1_compared"] += 1
        same = (
            (mine["label"], mine["excluded"]) == (r["label"], r["excluded"])
            and all(
                mine["verdicts"].get(f"study-v1/{p}") == r[p]
                for p in ("refusal", "side_effect", "pipeline")
            )
            if r["excluded"] is None
            else (mine["excluded"] == r["excluded"])
        )
        c["v1_differ"] += not same
        if r["variant"] == "whole" and r["excluded"] is None:
            c["v1_whole_analysed"] += 1
            c["v1_whole_positives"] += r["label"]
            c["v1_whole_pipeline_tp"] += r["label"] and r["pipeline"]
            c["v1_whole_pipeline_flagged"] += r["pipeline"]
c["v1_missing"] = len(iterate) * 3 - c["v1_compared"]


def critical(name: str) -> bool:
    from ziran.domain.tool_classifier import classify_tool  # the worktree's, byte-equal to study-v1

    return classify_tool(name).risk == "critical"


for rel in sorted(iterate):
    whole, pay = ours[(rel, "whole")], ours[(rel, "payload_whole")]
    if whole["excluded"] is not None:
        c["excluded_" + whole["excluded"]] += 1
        continue
    if pay["excluded"] is not None:
        c["payload_excluded_" + pay["excluded"]] += 1
        continue
    trace = probe.trace_of(json.loads((dl / "agentdojo" / rel).read_bytes()))
    t3, p1 = probe.t3(trace, critical), probe.p1(trace)
    c["replay_logs"] += 1
    c["t3_differ"] += whole["verdicts"][f"{patched}/deterministic"] != t3
    c["p1_differ"] += pay["verdicts"][f"{patched}/deterministic"] != p1
    c["t3_hits"] += t3
    c["p1_hits"] += p1
    c["p1_tp"] += p1 and whole["label"]
    c["p1_fp"] += p1 and not whole["label"]
    c["t3_tp"] += t3 and whole["label"]
    c["t3_fp"] += t3 and not whole["label"]
print(json.dumps(dict(sorted(c.items())), indent=1))
