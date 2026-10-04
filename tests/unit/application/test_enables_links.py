"""ENABLES edges link a vulnerability only to the capabilities implicated in it (spec 053)."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.enables_links import enabling_capabilities
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.agent_scanner.structure_import import import_structure
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType, NodeType
from ziran.domain.entities.capability import AgentCapability, CapabilityType, DangerousChain
from ziran.domain.entities.multi_agent import AgentNode, MultiAgentTopology, StateChannel
from ziran.domain.entities.phase import PhaseResult, ScanPhase

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit


def _cap(name: str, dangerous: bool = False, cap_id: str | None = None) -> AgentCapability:
    return AgentCapability(
        id=cap_id or f"tool_{name}", name=name, type=CapabilityType.TOOL, dangerous=dangerous
    )


def _graph(*caps: AgentCapability) -> AttackKnowledgeGraph:
    graph = AttackKnowledgeGraph()
    for cap in caps:
        graph.add_capability(cap.id, cap)
    return graph


def _invoked(*names: Any) -> dict[str, Any]:
    return {"side_effects": {"tools_invoked": list(names)}}


def _mixed() -> AttackKnowledgeGraph:
    return _graph(
        _cap("read_inbox"),
        _cap("send_email"),
        _cap("shell_execute", dangerous=True),
        _cap("get_weather"),
        _cap("read_file", dangerous=True),
    )


DANGEROUS = ["tool_shell_execute", "tool_read_file"]


class TestEnablingCapabilities:
    def test_match_by_name(self) -> None:
        assert enabling_capabilities(_mixed(), _invoked("send_email")) == ["tool_send_email"]

    def test_match_by_id(self) -> None:
        graph = _graph(_cap("Send mail", cap_id="send_email"), _cap("other", dangerous=True))
        assert enabling_capabilities(graph, _invoked("send_email")) == ["send_email"]

    def test_several_tools_keep_insertion_order(self) -> None:
        result = enabling_capabilities(_mixed(), _invoked("read_file", "read_inbox"))
        assert result == ["tool_read_inbox", "tool_read_file"]

    def test_match_by_id_and_name_no_duplicate(self) -> None:
        graph = _graph(_cap("send_email", cap_id="send_email"))
        assert enabling_capabilities(graph, _invoked("send_email", "send_email")) == ["send_email"]

    @pytest.mark.parametrize(
        "evidence",
        [
            {},
            {"side_effects": None},
            {"side_effects": "send_email"},
            {"side_effects": {"tools_invoked": "send_email"}},
            {"side_effects": {"tools_invoked": [None, 3, {"name": "send_email"}]}},
            _invoked(),
            _invoked("delete_everything"),
        ],
    )
    def test_malformed_or_unknown_falls_back_to_dangerous(self, evidence: Any) -> None:
        assert enabling_capabilities(_mixed(), evidence) == DANGEROUS

    def test_non_dict_capability_data_does_not_raise(self) -> None:
        graph = _mixed()
        graph.graph.nodes["tool_send_email"]["data"] = "corrupt"
        assert enabling_capabilities(graph, _invoked("send_email")) == DANGEROUS
        assert enabling_capabilities(graph, _invoked("tool_send_email")) == ["tool_send_email"]
        graph.graph.nodes["tool_get_weather"]["data"] = {"name": ["unhashable"]}
        assert enabling_capabilities(graph, _invoked("x")) == DANGEROUS

    def test_dangerous_fallback(self) -> None:
        assert enabling_capabilities(_mixed(), {}) == DANGEROUS

    def test_all_capabilities_fallback(self) -> None:
        graph = _graph(_cap("a"), _cap("b"), _cap("c"))
        assert enabling_capabilities(graph, {}) == ["tool_a", "tool_b", "tool_c"]

    def test_no_capabilities(self) -> None:
        assert enabling_capabilities(AttackKnowledgeGraph(), _invoked("x")) == []

    def test_non_capability_nodes_never_returned(self) -> None:
        graph = _graph(_cap("a"))
        graph.add_tool("send_email")
        graph.add_agent_node("agent_x", role="worker")
        graph.add_data_source("db")
        result = enabling_capabilities(graph, _invoked("send_email", "agent_x", "db"))
        assert result == ["tool_a"]

    def test_pure(self) -> None:
        graph = _mixed()
        before = graph.export_state()
        enabling_capabilities(graph, _invoked("send_email"))
        enabling_capabilities(graph, {})
        after = graph.export_state()
        assert (after["nodes"], after["edges"]) == (before["nodes"], before["edges"])


SIX_CAPS = [
    _cap("search_database", dangerous=True),
    _cap("send_email"),
    _cap("shell_execute", dangerous=True),
    _cap("get_weather"),
    _cap("calculator"),
    _cap("read_file", dangerous=True),
]


def _edges(graph: AttackKnowledgeGraph, edge_type: str) -> list[tuple[str, str, dict[str, Any]]]:
    return [(u, v, d) for u, v, d in graph.graph.edges(data=True) if d["edge_type"] == edge_type]


def _vulns(graph: AttackKnowledgeGraph) -> list[str]:
    return [n for n, _ in graph.get_nodes_by_type(NodeType.VULNERABILITY)]


def _phase(vulns: list[str], artifacts: dict[str, Any]) -> PhaseResult:
    return PhaseResult(
        phase=ScanPhase.VULNERABILITY_DISCOVERY,
        success=True,
        trust_score=0.5,
        duration_seconds=0.1,
        vulnerabilities_found=vulns,
        artifacts=artifacts,
    )


class TestScannerLinksImplicatedCapabilities:
    def _scanner(self, library: AttackLibrary, caps: list[AgentCapability]) -> AgentScanner:
        adapter = MockAgentAdapter(
            responses=["Sure! I have access to tools."], capabilities=caps, vulnerable=True
        )
        return AgentScanner(adapter=adapter, attack_library=library)

    def test_update_graph_edge_shape(self, shared_attack_library: AttackLibrary) -> None:
        scanner = self._scanner(shared_attack_library, SIX_CAPS)
        for cap in SIX_CAPS:
            scanner.graph.add_capability(cap.id, cap)
        scanner.graph.add_vulnerability("vid", "high")
        result = _phase(["vid"], {"vid": {"evidence": _invoked("send_email")}})
        scanner._update_graph_from_phase(result)
        enables = _edges(scanner.graph, EdgeType.ENABLES)
        assert [(u, v) for u, v, _ in enables] == [("tool_send_email", "vid")]
        assert enables[0][2]["phase"] == result.phase.value
        phase_node = f"phase_{result.phase.value}"
        assert [(u, v) for u, v, _ in _edges(scanner.graph, EdgeType.DISCOVERED_IN)] == [
            ("vid", phase_node)
        ]

    async def test_end_to_end_mock_scan(self, shared_attack_library: AttackLibrary) -> None:
        scanner = self._scanner(shared_attack_library, SIX_CAPS)
        campaign = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.VULNERABILITY_DISCOVERY]
        )
        vulns = _vulns(scanner.graph)
        enables = _edges(scanner.graph, EdgeType.ENABLES)
        assert vulns
        assert {u for u, _, _ in enables} == {"tool_shell_execute"}
        assert len(enables) == len(vulns)
        assert set(vulns) <= {p[-1] for p in campaign.critical_paths}
        assert len(campaign.critical_paths) == len(vulns) + 3


# ── Path preservation and fan-out (US3, US4.1, kept edge class) ──────────

Linker = Callable[[AttackKnowledgeGraph, PhaseResult], None]


def _legacy_link(graph: AttackKnowledgeGraph, result: PhaseResult) -> None:
    """Pre-053 ``_update_graph_from_phase`` body, captured from develop @ 7e1ef38."""
    phase_node_id = f"phase_{result.phase.value}"
    graph.graph.add_node(
        phase_node_id,
        node_type=NodeType.PHASE,
        phase=result.phase.value,
        trust_score=result.trust_score,
        success=result.success,
        duration_seconds=result.duration_seconds,
    )
    for vuln_id in result.vulnerabilities_found:
        graph.add_edge(vuln_id, phase_node_id, EdgeType.DISCOVERED_IN)
        for cap_id, _cap_data in graph.get_nodes_by_type(NodeType.CAPABILITY):
            graph.add_edge(
                cap_id,
                vuln_id,
                EdgeType.ENABLES,
                {"phase": result.phase.value},
            )


def _scanner_link(graph: AttackKnowledgeGraph, result: PhaseResult) -> None:
    scanner = AgentScanner(adapter=MockAgentAdapter())  # cached default library
    scanner.graph = graph
    scanner._update_graph_from_phase(result)


REPRESENTATIVE_CAPS = [
    _cap("read_inbox"),
    _cap("send_email"),
    _cap("shell_execute", dangerous=True),
    _cap("get_weather"),
    _cap("calculator"),
    _cap("read_file", dangerous=True),
]
PHASE_VULNS = ["vuln_exfil", "vuln_rce", "vuln_pi", "vuln_ghost"]
EXPECTED_PAIRS = {
    ("tool_send_email", "vuln_exfil"),
    ("tool_shell_execute", "vuln_rce"),
    ("tool_shell_execute", "vuln_pi"),
    ("tool_read_file", "vuln_pi"),
    ("tool_shell_execute", "vuln_ghost"),
    ("tool_read_file", "vuln_ghost"),
}


def _representative(link: Linker) -> AttackKnowledgeGraph:
    graph = AttackKnowledgeGraph()
    for cap in REPRESENTATIVE_CAPS:
        graph.add_capability(cap.id, cap)
        if cap.dangerous:  # exactly as AgentScanner._discover_and_map_capabilities
            graph.add_data_source(
                "sensitive_data", {"description": "Potentially accessible sensitive data"}
            )
            graph.add_edge(
                cap.id,
                "sensitive_data",
                EdgeType.ACCESSES_DATA,
                {"risk": "high", "capability_type": cap.type.value},
            )
    import_structure(
        graph,
        MultiAgentTopology(
            agents=[
                AgentNode(
                    id="n:mail",
                    name="mail",
                    capabilities=["tool_read_inbox", "tool_send_email"],
                    is_entry_point=True,
                )
            ],
            entry_point_id="n:mail",
            state_channels=[
                StateChannel(
                    name="messages", writers=["tool_read_inbox"], readers=["tool_send_email"]
                )
            ],
        ),
    )
    evidence = {
        "vuln_exfil": {"tool_calls": [{"tool": "send_email"}], **_invoked("send_email")},
        "vuln_rce": {"tool_calls": [{"tool": "shell_execute"}], **_invoked("shell_execute")},
        "vuln_pi": {"tool_calls": [], **_invoked()},
        "vuln_ghost": {
            "tool_calls": [{"tool": "delete_everything"}],
            **_invoked("delete_everything"),
        },
    }
    for vid in PHASE_VULNS:
        graph.add_vulnerability(vid, "high")
    link(graph, _phase(PHASE_VULNS, {v: {"evidence": e} for v, e in evidence.items()}))
    graph.add_chain_finding(
        DangerousChain(
            tools=["tool_read_inbox", "tool_send_email"],
            risk_level="high",
            vulnerability_type="data_exfiltration",
            exploit_description="inbox content can be mailed out",
        )
    )
    return graph


@pytest.fixture(scope="module")
def paths() -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    before = [tuple(p) for p in _representative(_legacy_link).find_all_attack_paths()]
    after = [tuple(p) for p in _representative(_scanner_link).find_all_attack_paths()]
    return before, after


class TestAttackPathsPreserved:
    def test_after_is_before_minus_non_implicated(self, paths: Any) -> None:
        before, after = paths
        assert set(after) < set(before)
        expected = {
            p for p in before if p[-1] not in PHASE_VULNS or (p[-2], p[-1]) in EXPECTED_PAIRS
        }
        assert set(after) == expected

    def test_endpoints_identical(self, paths: Any) -> None:
        before, after = paths
        assert {p[-1] for p in before} == {p[-1] for p in after}

    def test_named_paths_present(self, paths: Any) -> None:
        _, after = paths
        for path in [
            ("tool_read_inbox", "state:messages", "tool_send_email", "vuln_exfil"),
            ("tool_send_email", "vuln_exfil"),
            ("tool_shell_execute", "vuln_rce"),
            ("tool_shell_execute", "sensitive_data"),
            ("tool_shell_execute", "vuln_pi"),
            ("tool_read_file", "vuln_pi"),
            ("tool_shell_execute", "vuln_ghost"),
            ("tool_read_file", "vuln_ghost"),
        ]:
            assert path in after

    def test_non_enables_paths_identical(self, paths: Any) -> None:
        before, after = paths
        kept_before = [p for p in before if p[-1] not in PHASE_VULNS]
        assert kept_before == [p for p in after if p[-1] not in PHASE_VULNS]
        assert any(p[-1].startswith("composition::") for p in kept_before)
        assert any(p[-1] == "sensitive_data" for p in kept_before)


def _count_enables(graph: AttackKnowledgeGraph) -> int:
    return len(_edges(graph, EdgeType.ENABLES))


class TestFanOut:
    @staticmethod
    def _build(link: Linker, caps: list[AgentCapability], artifacts: dict[str, Any]) -> int:
        graph = _graph(*caps)
        for vid in artifacts:
            graph.add_vulnerability(vid, "high")
        link(graph, _phase(list(artifacts), artifacts))
        return _count_enables(graph)

    def test_cross_product_gone(self) -> None:
        caps = [_cap(f"t{i}", dangerous=i < 2) for i in range(10)]
        artifacts: dict[str, Any] = {
            f"v{i}": {"evidence": _invoked(caps[i % 10].name)} for i in range(15)
        }
        artifacts.update({f"v{i}": {"evidence": {"tool_calls": []}} for i in range(15, 20)})
        new, legacy = (
            self._build(_scanner_link, caps, artifacts),
            self._build(_legacy_link, caps, artifacts),
        )
        assert (new, legacy) == (25, 200)
        assert new < legacy / 4

    def test_benign_agent_without_tool_calls_keeps_cross_product(self) -> None:
        caps = [_cap("a"), _cap("b"), _cap("c")]
        artifacts = {"v1": {"evidence": {}}, "v2": {}}
        assert self._build(_scanner_link, caps, artifacts) == 6
        assert self._build(_legacy_link, caps, artifacts) == 6
