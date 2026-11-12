"""Rebuild trace_judge_spike_render.json's request text with the spike's own renderer.

Run from a git archive of taoq-ai/ziran-paper (never a live checkout), with ``python -I``:

    python -I spike_render.py <paper tree> <out.json> <log.json>

It renders the synthetic AgentDojo log with ``g11_judge_spike.render_trace``, its call evidence
from ``g11_dev_sets.calls_view``, after prompt v1 as the spike's ``request_rows`` joins them.
"""

import json
import sys
from pathlib import Path


def main(paper: Path, out: Path, log_path: Path) -> None:
    sys.path.insert(0, str(paper / "study" / "scripts"))
    import g11_judge_spike as js  # the paper tree is known only at run time

    log = json.loads(log_path.read_text())
    view = js.ds.calls_view(js.gp.trace_of(log), lambda name: False)
    text = js.render_trace(log, view)
    prompt = (paper / "specs" / "035-g11-judge-spike" / "prompt-v1.md").read_bytes()
    request = prompt.decode().rstrip("\n") + "\n\n" + text
    out.write_text(json.dumps({"view": view, "request_text": request}, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
