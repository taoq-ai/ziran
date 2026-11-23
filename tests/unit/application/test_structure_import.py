"""Tests for importing an adapter-reported agent structure into the knowledge graph (spec 050)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import networkx as nx
import pytest
import structlog
from structlog.testing import capture_logs

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner import structure_import as si_mod
from ziran.application.agent_scanner.result_builder import ResultBuilder
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.agent_scanner.structure_import import (
    MAX_CO_RESIDENT_TOOLS,
    STATE_NODE_PREFIX,
    import_adapter_structure,
    import_structure,
)
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.pentesting.tools.graph import analyze_graph
from ziran.domain.entities.attack import TokenUsage
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.multi_agent import (
    AgentEdge,
    AgentNode,
    DelegationPattern,
    MultiAgentTopology,
    StateChannel,
)

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit

READ = "tool_read_file"
SEND = "tool_http_request"


def _cap(cap_id: str, dangerous: bool = True) -> AgentCapability:
    return AgentCapability(
        id=cap_id,
        name=cap_id.removeprefix("tool_"),
        type=CapabilityType.TOOL,
        dangerous=dangerous,
    )


def _topology() -> MultiAgentTopology:
    return MultiAgentTopology(
        agents=[
            AgentNode(
                id="n:a",
                name="a",
                role="router",
                framework="test",
                capabilities=[READ],
                is_entry_point=True,
            ),
            AgentNode(id="n:b", name="b", framework="test", capabilities=[SEND]),
        ],
        edges=[
            AgentEdge(
                source_id="n:a",
                target_id="n:b",
                delegation=DelegationPattern.FULL_CONTEXT,
                conditional=True,
                branch_label="go",
            ),
            AgentEdge(source_id="n:b", target_id="n:a", delegation=DelegationPattern.FULL_CONTEXT),
        ],
        entry_point_id="n:a",
        state_channels=[StateChannel(name="messages", writers=[READ, SEND], readers=[READ, SEND])],
    )


def _graph(*caps: AgentCapability) -> AttackKnowledgeGraph:
    graph = AttackKnowledgeGraph()
    for cap in caps or (_cap(READ), _cap(SEND)):
        graph.add_capability(cap.id, cap)
    return graph


def _edges(graph: AttackKnowledgeGraph, edge_type: str) -> list[dict[str, Any]]:
    return [e for e in graph.export_state()["edges"] if e["edge_type"] == edge_type]


class TestImportStructure:
    def test_nodes_and_edges(self) -> None:
        graph = _graph()
        import_structure(graph, _topology())
        state = graph.export_state()
        nodes = {n["id"]: n for n in state["nodes"]}

        a = nodes["n:a"]
        assert a["node_type"] == "agent"
        assert a["role"] == "router"
        assert a["name"] == "a"
        assert a["framework"] == "test"
        assert a["is_entry_point"] is True
        assert a["capabilities"] == [READ]
        assert nodes["n:b"]["role"] == "worker"

        delegations = {(e["source"], e["target"]): e for e in _edges(graph, "delegates_to")}
        assert set(delegations) == {("n:a", "n:b"), ("n:b", "n:a")}
        assert delegations["n:a", "n:b"]["delegation_pattern"] == "full_context"
        assert delegations["n:a", "n:b"]["conditional"] is True
        assert delegations["n:a", "n:b"]["branch_label"] == "go"
        assert delegations["n:b", "n:a"]["conditional"] is False
        assert delegations["n:b", "n:a"]["branch_label"] is None

        uses = {(e["source"], e["target"]) for e in _edges(graph, "uses_tool")}
        assert uses == {("n:a", READ), ("n:b", SEND)}

        state_node = nodes[f"{STATE_NODE_PREFIX}messages"]
        assert state_node["node_type"] == "agent_state"
        assert state_node["name"] == "state.messages"
        assert state_node["channel"] == "messages"
        assert state_node["writers"] == [READ, SEND]
        assert state_node["readers"] == [READ, SEND]

        access = {
            (e["source"], e["target"], e.get("access")) for e in _edges(graph, "accesses_data")
        }
        assert (READ, "state:messages", "write") in access
        assert (SEND, "state:messages", "write") in access
        assert ("state:messages", READ, "read") in access
        assert ("state:messages", SEND, "read") in access

    def test_chain_found_only_with_structure(self) -> None:
        flat = _graph()
        assert not [
            c
            for c in ToolChainAnalyzer(flat).analyze()
            if c.vulnerability_type == "data_exfiltration"
        ]

        graph = _graph()
        import_structure(graph, _topology())
        chains = [
            c
            for c in ToolChainAnalyzer(graph).analyze()
            if c.vulnerability_type == "data_exfiltration"
        ]
        assert any(
            c.chain_type == "indirect"
            and c.graph_path == [READ, "state:messages", SEND]
            and "possible via shared state" in c.exploit_description
            for c in chains
        )

    def test_harmless_tools_add_no_attack_path_or_chain(self) -> None:
        weather = "tool_get_weather"
        graph = _graph(_cap(weather, dangerous=False))
        before = graph.find_all_attack_paths()
        topo = MultiAgentTopology(
            agents=[AgentNode(id="n:w", name="w", capabilities=[weather])],
            state_channels=[StateChannel(name="messages", writers=[weather], readers=[weather])],
        )
        import_structure(graph, topo)
        assert graph.find_all_attack_paths() == before
        assert ToolChainAnalyzer(graph).analyze() == []

    def test_unknown_ids_are_skipped(self) -> None:
        graph = _graph()
        topo = MultiAgentTopology(
            agents=[AgentNode(id="n:a", name="a", capabilities=["tool_missing"])],
            edges=[AgentEdge(source_id="n:a", target_id="n:ghost")],
            state_channels=[StateChannel(name="m", writers=["tool_missing"], readers=["tool_x"])],
        )
        nodes_before = graph.node_count
        import_structure(graph, topo)
        assert graph.node_count == nodes_before + 1  # only the agent node
        assert graph.edge_count == 0
        assert "n:ghost" not in graph.graph
        assert "state:m" not in graph.graph

    def test_edge_count_is_linear(self) -> None:
        ids = [f"tool_t{i}" for i in range(30)]
        graph = _graph(*(_cap(i, dangerous=False) for i in ids))
        topo = MultiAgentTopology(
            agents=[AgentNode(id="n:all", name="all", capabilities=ids)],
            state_channels=[StateChannel(name="messages", writers=ids, readers=ids)],
        )
        import_structure(graph, topo)
        assert len(_edges(graph, "accesses_data")) == 60
        assert len(_edges(graph, "uses_tool")) == 30
        ToolChainAnalyzer(graph).analyze()

    def test_dense_routed_graph_stays_fast(self) -> None:
        # Every node routes to every other node and to "tools": the agent sub-graph has
        # millions of simple cycles, none of which can contain a tool.
        names = [f"n:{i}" for i in range(12)]
        topo = MultiAgentTopology(
            agents=[
                *(AgentNode(id=n, name=n) for n in names),
                AgentNode(id="n:tools", name="tools", capabilities=[READ, SEND]),
            ],
            edges=[
                AgentEdge(source_id=a, target_id=b, conditional=True)
                for a in names
                for b in [*names, "n:tools"]
                if a != b
            ],
            state_channels=[
                StateChannel(name="messages", writers=[READ, SEND], readers=[READ, SEND])
            ],
        )
        graph = _graph()
        import_structure(graph, topo)
        start = time.perf_counter()
        chains = ToolChainAnalyzer(graph).analyze()
        assert time.perf_counter() - start < 2.0
        assert any(
            c.vulnerability_type == "data_exfiltration" and c.chain_type == "indirect"
            for c in chains
        )


class _StructureAdapter(MockAgentAdapter):
    def __init__(self, structure: Any, capabilities: list[AgentCapability] | None = None) -> None:
        super().__init__(capabilities=capabilities)
        self._structure = structure

    async def discover_structure(self) -> Any:
        if isinstance(self._structure, Exception):
            raise self._structure
        return self._structure


class TestImportAdapterStructure:
    @pytest.fixture(autouse=True)
    def _fresh_logger(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(si_mod, "logger", structlog.get_logger())

    async def test_default_adapter_leaves_graph_unchanged(self) -> None:
        graph = _graph()
        before = (graph.node_count, graph.edge_count)
        assert await import_adapter_structure(MockAgentAdapter(), graph, []) is None
        assert (graph.node_count, graph.edge_count) == before

    async def test_failure_is_logged_not_raised(self) -> None:
        graph = _graph()
        with capture_logs() as logs:
            result = await import_adapter_structure(
                _StructureAdapter(RuntimeError("boom")), graph, []
            )
        assert result is None
        hits = [e for e in logs if e["event"] == "structure_discovery_failed"]
        assert hits and hits[0]["error"] == "RuntimeError: boom"

    async def test_non_topology_is_ignored(self) -> None:
        graph = _graph()
        before = graph.node_count
        with capture_logs() as logs:
            result = await import_adapter_structure(_StructureAdapter({"agents": []}), graph, [])
        assert result is None
        assert graph.node_count == before
        hits = [e for e in logs if e["event"] == "structure_discovery_ignored"]
        assert hits and hits[0]["type"] == "dict"

    async def test_topology_is_imported(self) -> None:
        graph = _graph()
        topo = _topology()
        with capture_logs() as logs:
            assert await import_adapter_structure(_StructureAdapter(topo), graph, []) is topo
        assert "state:messages" in graph.graph
        hits = [e for e in logs if e["event"] == "structure_imported"]
        assert hits and (hits[0]["agents"], hits[0]["edges"], hits[0]["channels"]) == (2, 2, 1)


def _build(graph: AttackKnowledgeGraph) -> tuple[Any, list[Any]]:
    return ResultBuilder(graph, "flat").build(
        campaign_id="c",
        phase_results=[],
        attack_results=[],
        campaign_tokens=TokenUsage(),
        coverage_value="essential",
        max_concurrent_attacks=1,
        duration=0.0,
        capabilities_count=0,
    )


def _exfil(chains: list[Any]) -> list[Any]:
    return [c for c in chains if c.vulnerability_type == "data_exfiltration"]


def _no_cycle_search(*_: Any) -> list[Any]:
    # fail fast instead of hanging: cycle enumeration is exponential on a complete graph
    raise AssertionError("cycle search ran on a co-resident graph")


_WALKERS = (
    "has_path",
    "all_simple_paths",
    "descendants",
    "simple_cycles",
    "betweenness_centrality",
)


@pytest.fixture
def walker_guard(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Fail fast when a graph walker is handed a co-resident edge; returns calls per walker."""
    calls = dict.fromkeys(_WALKERS, 0)
    clean: dict[int, Any] = {}  # keeps each checked graph alive, so no id is reused

    def guard(name: str) -> None:
        real = getattr(nx, name)

        def walker(g: Any, *args: Any, **kwargs: Any) -> Any:
            calls[name] += 1
            if id(g) not in clean:
                assert not any(d.get("co_resident") for _, _, d in g.edges(data=True)), name
                clean[id(g)] = g
            return real(g, *args, **kwargs)

        monkeypatch.setattr(nx, name, walker)

    for name in _WALKERS:
        guard(name)
    return calls


class TestCoResidentTools:
    """Spec 086: tools no structure links are co-resident and get CAN_CHAIN_TO edges."""

    async def test_no_structure_links_every_tool_pair(self) -> None:
        skill = AgentCapability(id="role", name="role", type=CapabilityType.SKILL)
        caps = [_cap(READ), _cap(SEND), skill]
        graph = _graph(*caps)
        await import_adapter_structure(MockAgentAdapter(), graph, caps)
        assert graph.has_co_resident_tools()
        chains = {(e["source"], e["target"]) for e in _edges(graph, "can_chain_to")}
        assert chains == {(READ, SEND), (SEND, READ)}

    async def test_state_channel_keeps_only_real_edges(self) -> None:
        graph = _graph()
        adapter = _StructureAdapter(_topology())
        await import_adapter_structure(adapter, graph, [_cap(READ), _cap(SEND)])
        assert not graph.has_co_resident_tools()
        assert _edges(graph, "can_chain_to") == []

    async def test_topology_without_tool_links_is_co_resident(self) -> None:
        topo = MultiAgentTopology(agents=[AgentNode(id="n:a", name="a", capabilities=[READ, SEND])])
        graph = _graph()
        await import_adapter_structure(_StructureAdapter(topo), graph, [_cap(READ), _cap(SEND)])
        assert graph.has_co_resident_tools()

    def test_fifteen_flat_tools_skip_cycles(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ToolChainAnalyzer, "_find_chain_cycles", _no_cycle_search)
        caps = [_cap(f"tool_read_file_{i}") for i in range(14)] + [_cap(SEND)]
        graph = _graph(*caps)
        graph.add_co_resident_tools([c.id for c in caps])
        _, chains = _build(graph)
        assert chains and not any(c.chain_type == "cycle" for c in chains)

    async def test_linking_channel_without_agents_adds_no_edges(self) -> None:
        # read_file writes, http_request reads: linked, so the unrelated tool gets no set either
        query = "tool_query_database"
        topo = MultiAgentTopology(
            state_channels=[StateChannel(name="messages", writers=[READ], readers=[SEND])]
        )
        caps = [_cap(READ), _cap(SEND), _cap(query)]
        graph = _graph(*caps)
        await import_adapter_structure(_StructureAdapter(topo), graph, caps)
        assert not graph.has_co_resident_tools()

    async def test_graph_node_with_two_linked_tools_adds_no_edges(self) -> None:
        topo = MultiAgentTopology(
            agents=[AgentNode(id="n:tools", name="tools", capabilities=[READ, SEND])],
            state_channels=[
                StateChannel(name="messages", writers=[READ, SEND], readers=[READ, SEND])
            ],
        )
        graph = _graph()
        await import_adapter_structure(_StructureAdapter(topo), graph, [_cap(READ), _cap(SEND)])
        assert not graph.has_co_resident_tools()

    async def test_tool_cap_skips_edges_and_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(si_mod, "logger", structlog.get_logger())
        caps = [_cap(f"tool_read_file_{i}") for i in range(MAX_CO_RESIDENT_TOOLS)]
        caps.append(_cap(SEND))
        graph = _graph(*caps)
        with capture_logs() as logs:
            await import_adapter_structure(MockAgentAdapter(), graph, caps)
            await import_adapter_structure(MockAgentAdapter(), graph, caps)  # a second campaign
        assert _edges(graph, "can_chain_to") == []
        hits = [e for e in logs if e["event"] == "co_resident_tools_skipped"]
        assert hits and (hits[0]["tools"], hits[0]["cap"]) == (101, MAX_CO_RESIDENT_TOOLS)
        # the result builder carries the skip into the result, once
        [warning] = _build(graph)[0].warnings
        assert "101 tools" in warning and f"cap of {MAX_CO_RESIDENT_TOOLS}" in warning
        assert _build(_graph())[0].model_dump()["metadata"].get("warnings") is None

    async def test_repeated_discovery_adds_the_edges_once(self) -> None:
        caps = [_cap(READ), _cap(SEND)]
        graph = _graph(*caps)
        for _ in range(2):  # the pentest agent runs one campaign per step on the same graph
            await import_adapter_structure(MockAgentAdapter(), graph, caps)
        assert len(_edges(graph, "can_chain_to")) == 2

    async def test_tool_cap_counts_all_sets(self) -> None:
        # two agents of 60 tools: 120 tools in sets is over the cap, so neither set gets edges
        ids = [[f"tool_a{a}_{i}" for i in range(60)] for a in range(2)]
        topo = MultiAgentTopology(
            agents=[AgentNode(id=f"n:{a}", name=str(a), capabilities=ids[a]) for a in range(2)]
        )
        caps = [_cap(i) for group in ids for i in group]
        graph = _graph(*caps)
        await import_adapter_structure(_StructureAdapter(topo), graph, caps)
        assert not graph.has_co_resident_tools()

    async def test_tool_cap_allows_exactly_the_cap(self) -> None:
        caps = [_cap(f"tool_t{i}") for i in range(MAX_CO_RESIDENT_TOOLS)]
        graph = _graph(*caps)
        await import_adapter_structure(MockAgentAdapter(), graph, caps)
        n = MAX_CO_RESIDENT_TOOLS
        assert len(_edges(graph, "can_chain_to")) == n * (n - 1)

    def test_centrality_skipped_on_big_co_resident_graph(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_centrality(*_: Any, **__: Any) -> dict[str, float]:
            raise AssertionError("betweenness ran on a big co-resident graph")

        graph = _graph(*(_cap(f"tool_t{i}", dangerous=False) for i in range(801)))
        graph.add_co_resident_tools(["tool_t0", "tool_t1"])
        monkeypatch.setattr(nx, "betweenness_centrality", no_centrality)
        ToolChainAnalyzer(graph).analyze()

    def test_centrality_still_runs_on_big_plain_graph(self, walker_guard: dict[str, int]) -> None:
        graph = _graph(*(_cap(f"tool_t{i}", dangerous=False) for i in range(801)))
        ToolChainAnalyzer(graph).analyze()
        assert walker_guard["betweenness_centrality"] == 1

    def test_only_the_pair_rule_reads_co_resident_edges(self, walker_guard: dict[str, int]) -> None:
        """Spec 086 design rule: every walker but the direct pair rule gets the structure view."""
        shared = "tool_shared"
        graph = _graph(_cap(READ), _cap(SEND), _cap(shared))
        graph.add_co_resident_tools([READ, shared])
        graph.add_co_resident_tools([shared, SEND])
        # real structure beside the co-resident sets: a channel from read_file to http_request
        import_structure(
            graph,
            MultiAgentTopology(
                agents=[AgentNode(id="n:a", name="a"), AgentNode(id="n:b", name="b")],
                edges=[AgentEdge(source_id="n:a", target_id="n:b")],
                state_channels=[StateChannel(name="m", writers=[READ], readers=[SEND])],
            ),
        )
        real_path = [READ, "state:m", SEND]

        chains = ToolChainAnalyzer(graph).analyze(include_cycles=True)
        exfil = [c for c in _exfil(chains) if c.tools == [READ, SEND]]
        assert [c.graph_path for c in exfil] == [real_path]  # never read -> shared -> send
        assert graph.find_attack_paths(READ, SEND) == [real_path]
        assert {tuple(p) for p in graph.get_cross_agent_attack_paths()} == {("n:a", "n:b")}
        assert graph.get_critical_nodes()
        graph.export_state()
        _build(graph)
        assert analyze_graph(graph)["dangerous_chains"]  # it swallows a failed chain analysis
        assert all(walker_guard.values()), walker_guard

    async def test_two_agents_sharing_a_tool_stay_fast(self, walker_guard: dict[str, int]) -> None:
        # 50 tools each (the cap, counted per set), joined by one shared tool: indirect search
        # between the two cliques never finished before it left the co-resident edges out
        sets = [
            [
                *(f"tool_read_file_{a}{i}" for i in range(25)),
                *(f"tool_http_request_{a}{i}" for i in range(24)),
                "tool_shared",
            ]
            for a in "ab"
        ]
        topo = MultiAgentTopology(
            agents=[AgentNode(id=f"n:{i}", name=str(i), capabilities=s) for i, s in enumerate(sets)]
        )
        caps = [_cap(t) for t in dict.fromkeys(t for s in sets for t in s)]
        graph = _graph(*caps)
        await import_adapter_structure(_StructureAdapter(topo), graph, caps)
        assert len(_edges(graph, "can_chain_to")) == 2 * 50 * 49
        start = time.perf_counter()
        _, chains = _build(graph)
        assert time.perf_counter() - start < 5.0
        assert walker_guard["has_path"]  # the cross-agent pairs were searched, on the view
        for s in sets:
            assert any(c.chain_type == "direct" and set(c.tools) <= set(s) for c in _exfil(chains))
        assert all(any(set(c.tools) <= set(s) for s in sets) for c in chains)  # none crosses

    async def test_hundred_flat_tools_stay_fast(self, walker_guard: dict[str, int]) -> None:
        caps = [
            _cap(f"tool_{kind}_{i}") for kind in ("read_file", "http_request") for i in range(50)
        ]
        graph = _graph(*caps)
        await import_adapter_structure(MockAgentAdapter(), graph, caps)
        assert graph.has_co_resident_tools()
        start = time.perf_counter()
        _, chains = _build(graph)
        assert time.perf_counter() - start < 5.0
        assert len(_exfil(chains)) == 50 * 50
        assert walker_guard["betweenness_centrality"] and walker_guard["all_simple_paths"]

    async def test_thousand_tool_mcp_scan_stays_bounded(
        self, shared_attack_library: AttackLibrary
    ) -> None:
        import json

        import httpx

        from ziran.domain.entities.target import ProtocolType, TargetConfig
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter
        from ziran.infrastructure.adapters.protocols.mcp_handler import MCPProtocolHandler

        names = [f"read_file_{i}" for i in range(500)] + [f"http_request_{i}" for i in range(500)]

        async def server(request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["method"] == "tools/list":
                result = {"tools": [{"name": n} for n in names]}
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})
            error = {"code": -32601, "message": "no such method"}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": error})

        config = TargetConfig(
            url="https://mcp.example.com", protocol=ProtocolType.MCP, probe_delay=0
        )
        adapter = HttpAgentAdapter(config)
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(server))
        adapter._handler = MCPProtocolHandler(adapter._client, config)
        scanner = AgentScanner(adapter=adapter, attack_library=shared_attack_library)
        start = time.perf_counter()
        try:
            await scanner._discover_and_map_capabilities()
        finally:
            await adapter._client.aclose()
        assert _edges(scanner.graph, "can_chain_to") == []
        _build(scanner.graph)
        assert time.perf_counter() - start < 10.0

    def test_cycle_search_never_runs_on_co_resident_graph(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ToolChainAnalyzer, "_find_chain_cycles", _no_cycle_search)
        caps = [_cap(f"tool_read_file_{i}") for i in range(11)] + [_cap(SEND)]
        graph = _graph(*caps)
        graph.add_co_resident_tools([c.id for c in caps])
        assert ToolChainAnalyzer(graph).analyze()
        # the pentest agent's graph tool runs the same analysis on every step
        assert analyze_graph(graph)["dangerous_chains"]

    def test_marker_survives_export_and_import(self) -> None:
        graph = _graph()
        graph.add_co_resident_tools([READ, SEND])
        restored = AttackKnowledgeGraph()
        restored.import_state(graph.export_state())
        assert restored.has_co_resident_tools()

    async def test_self_loop_channel_is_no_tool_link(self) -> None:
        # one tool writes and reads its own channel: that links no two tools
        topo = MultiAgentTopology(
            state_channels=[StateChannel(name="own", writers=[READ], readers=[READ])]
        )
        graph = _graph()
        await import_adapter_structure(_StructureAdapter(topo), graph, [_cap(READ), _cap(SEND)])
        assert graph.has_co_resident_tools()
        assert any(
            c.vulnerability_type == "data_exfiltration" and c.tools == [READ, SEND]
            for c in ToolChainAnalyzer(graph).analyze()
        )

    async def test_handoff_team_links_tools_per_agent(self) -> None:
        query, mail = "tool_query_database", "tool_send_email"
        topo = MultiAgentTopology(
            agents=[
                AgentNode(id="n:triage", name="triage", is_entry_point=True),
                AgentNode(id="n:billing", name="billing", capabilities=[query]),
                AgentNode(id="n:mailer", name="mailer", capabilities=[mail]),
            ],
            edges=[
                AgentEdge(source_id="n:triage", target_id="n:billing"),
                AgentEdge(source_id="n:triage", target_id="n:mailer"),
            ],
        )
        caps = [_cap(query), _cap(mail)]
        graph = _graph(*caps)
        await import_adapter_structure(_StructureAdapter(topo), graph, caps)
        assert not any(
            c.vulnerability_type == "data_exfiltration" and set(c.tools) == {query, mail}
            for c in ToolChainAnalyzer(graph).analyze()
        )
        # the same two tools on one agent do chain
        flat = _graph(*caps)
        await import_adapter_structure(MockAgentAdapter(), flat, caps)
        assert any(
            c.vulnerability_type == "data_exfiltration" and c.tools == [query, mail]
            for c in ToolChainAnalyzer(flat).analyze()
        )

    async def test_unlisted_tools_form_one_set(self) -> None:
        topo = MultiAgentTopology(agents=[AgentNode(id="n:a", name="a")])
        graph = _graph()
        await import_adapter_structure(_StructureAdapter(topo), graph, [_cap(READ), _cap(SEND)])
        chains = {(e["source"], e["target"]) for e in _edges(graph, "can_chain_to")}
        assert chains == {(READ, SEND), (SEND, READ)}


async def test_scanner_imports_adapter_structure(shared_attack_library: AttackLibrary) -> None:
    adapter = _StructureAdapter(_topology(), capabilities=[_cap(READ), _cap(SEND)])
    scanner = AgentScanner(adapter=adapter, attack_library=shared_attack_library)
    await scanner._discover_and_map_capabilities()
    assert "state:messages" in scanner.graph.graph
    assert len(_edges(scanner.graph, "delegates_to")) == 2
