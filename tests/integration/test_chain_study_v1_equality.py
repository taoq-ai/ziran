"""Integration: with no override the analyzer still reports every study-v1 chain (spec 066).

``tests/fixtures/chains/study_v1_chains.json`` holds the chains of ziran ``study-v1``
(32281c77), cycles off, on every agent of ``benchmarks/ground_truth/agents`` and on a
two-tool agent for each of the 126 pattern pairs; ``specs/066-v2-role-typing/plan.md``
gives the command that wrote it. With ``typed=True`` typed chains are added beside them,
never in their place; without it the output is study-v1's.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from benchmarks.ground_truth.run import _build_graph_for_agent, load_agents
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.role_typing import TYPED_VULNERABILITY_TYPES

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parents[1] / "fixtures" / "chains" / "study_v1_chains.json"
KEEP = {"tools", "risk_level", "vulnerability_type", "chain_type", "graph_path", "risk_score"}


def _chains(tools: list[str], *, typed: bool = True) -> tuple[list[dict[str, Any]], list[Any]]:
    graph = _build_graph_for_agent([SimpleNamespace(id=t) for t in tools])
    found = ToolChainAnalyzer(graph, typed=typed).analyze(include_cycles=False)
    table = [c.model_dump(mode="json", include=KEEP) for c in found if not c.typed]
    return table, [c for c in found if c.typed]


def _key(c: dict[str, Any]) -> str:
    return json.dumps(c, sort_keys=True)


def _fixture() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data


def test_every_agent_keeps_its_study_v1_chains() -> None:
    v1 = _fixture()["agents"]
    agents = load_agents()
    assert sorted(v1) == sorted(agents)
    assert len(v1) == 22
    for agent_id, expected in v1.items():
        assert [t.id for t in agents[agent_id].tools] == expected["tools"], agent_id
        for typed in (False, True):
            table, added = _chains(expected["tools"], typed=typed)
            assert sorted(map(_key, table)) == sorted(map(_key, expected["chains"])), agent_id
            assert typed or not added  # off by default: the output is study-v1's


def test_every_pattern_pair_keeps_its_study_v1_chains() -> None:
    v1 = _fixture()["patterns"]
    assert len(v1) == 126
    for expected in v1:
        for typed in (False, True):
            table, added = _chains(expected["tools"], typed=typed)
            assert sorted(map(_key, table)) == sorted(map(_key, expected["chains"])), expected[
                "tools"
            ]
            assert typed or not added


def test_typed_chains_are_marked_and_counted_apart() -> None:
    v1 = _fixture()["agents"]
    typed_total = 0
    for expected in v1.values():
        table, typed = _chains(expected["tools"])
        pairs = {tuple(c["tools"]) for c in table}
        for c in typed:
            assert c.vulnerability_type in TYPED_VULNERABILITY_TYPES.values()
            assert c.evidence["role_source"].keys() == set(c.tools)
            assert tuple(c.tools) not in pairs  # a pair the table holds is not typed again
        typed_total += len(typed)
    assert typed_total > 0
