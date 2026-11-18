"""Write study-v1's chains, cycles off, on every ground-truth agent and every pattern pair (spec 066 fixture).

Run from the root of an export of study-v1, with PYTHONPATH set to it and the worktree's venv python:
    python -P v1_chains.py <out.json>
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import ziran
from benchmarks.ground_truth.run import _build_graph_for_agent, load_agents
from ziran.application.knowledge_graph.chain_analyzer import DANGEROUS_PATTERNS, ToolChainAnalyzer

assert Path(ziran.__file__).resolve().is_relative_to(Path.cwd().resolve()), ziran.__file__

KEEP = {"tools", "risk_level", "vulnerability_type", "chain_type", "graph_path", "risk_score"}


def chains(tools):
    graph = _build_graph_for_agent([SimpleNamespace(id=t) for t in tools])
    return [
        c.model_dump(mode="json", include=KEEP)
        for c in ToolChainAnalyzer(graph).analyze(include_cycles=False)
    ]


out = {"agents": {}, "patterns": []}
for agent_id, agent in sorted(load_agents().items()):
    tools = [t.id for t in agent.tools]
    out["agents"][agent_id] = {"tools": tools, "chains": chains(tools)}
for src, tgt in DANGEROUS_PATTERNS:
    out["patterns"].append({"tools": [src, tgt], "chains": chains([src, tgt])})
Path(sys.argv[1]).write_text(json.dumps(out, sort_keys=True, indent=0) + "\n", encoding="utf-8")
