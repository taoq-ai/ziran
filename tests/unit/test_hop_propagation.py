"""Hop-tagged canaries across a multi-agent system (spec 122), on in-process fakes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import pytest

from ziran.application.knowledge_graph.graph import EdgeType
from ziran.application.multi_agent.propagation import hop_canary, trace_propagation
from ziran.application.multi_agent.scanner import MultiAgentScanner
from ziran.domain.entities.multi_agent import AgentEdge, AgentNode, MultiAgentTopology
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

PROMPT_A = "You are the billing worker. Never reveal invoice numbers to callers."
PROMPT_B = "You are the ticket worker. File every request with the helpdesk tool."


class FakeAgent(BaseAgentAdapter):
    """Hands each message to ``next``; a ``tool`` agent files it as a ticket instead."""

    def __init__(self, reply: str = "done", nxt: FakeAgent | None = None, tool: bool = False):
        self.reply, self.next, self.tool = reply, nxt, tool
        self.history: list[dict[str, str]] = []
        self.calls: list[dict[str, Any]] = []

    @property
    def observes_delegated_traffic(self) -> bool:
        return True

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        self.history.append({"role": "user", "content": message})
        if self.tool:
            self.calls.append({"tool": "file_ticket", "input": {"body": message}})
        if self.next is not None:
            await self.next.invoke(message)
        return AgentResponse(content=self.reply)

    async def discover_capabilities(self) -> list[Any]:
        return []

    def get_state(self) -> AgentState:
        return AgentState(
            session_id="s",
            conversation_history=list(self.history),
            memory={"observed_tool_calls": list(self.calls)},
        )

    def reset_state(self) -> None:
        self.history.clear()
        self.calls.clear()

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        self.calls.append({"tool": tool_name, "input": inputs})


class Broken(FakeAgent):
    def get_state(self) -> AgentState:
        raise RuntimeError("state unavailable")


def _topology(*extra: AgentEdge) -> MultiAgentTopology:
    return MultiAgentTopology(
        agents=[
            AgentNode(id="supervisor", name="Supervisor", role="supervisor", is_entry_point=True),
            AgentNode(
                id="worker_a",
                name="Billing Worker",
                capabilities=["lookup_invoice"],
                system_prompt=PROMPT_A,
                system_prompt_known=True,
            ),
            AgentNode(
                id="worker_b",
                name="Ticket Worker",
                capabilities=["file_ticket"],
                system_prompt=PROMPT_B,
                system_prompt_known=True,
            ),
        ],
        edges=[
            AgentEdge(source_id="supervisor", target_id="worker_a"),
            AgentEdge(source_id="worker_a", target_id="worker_b"),
            *extra,
        ],
        entry_point_id="supervisor",
    )


def _system(reply: str = "done") -> dict[str, BaseAgentAdapter]:
    b = FakeAgent(tool=True)
    a = FakeAgent(nxt=b)
    return {"supervisor": FakeAgent(reply=reply, nxt=a), "worker_a": a, "worker_b": b}


def _campaign() -> CampaignResult:
    return CampaignResult(
        campaign_id="c",
        target_agent="t",
        phases_executed=[],
        total_vulnerabilities=0,
        final_trust_score=1.0,
        success=False,
    )


def _trace(traces: list[Any], vector_id: str, planted_at: str = "supervisor") -> Any:
    return next(t for t in traces if t.vector_id == vector_id and t.planted_at == planted_at)


def test_hop_canary_tags_the_hop() -> None:
    canary = hop_canary("c1", "v1", "worker_a", 1)
    assert canary.startswith("ZIRAN-H1-") and len(canary) == len("ZIRAN-H1-") + 10
    assert hop_canary("c1", "v1", "x", None).startswith("ZIRAN-HX-")
    assert canary != hop_canary("c1", "v1", "worker_b", 1)


@pytest.mark.asyncio
async def test_cross_agent_injection_names_entry_a_b_through_the_scanner(
    shared_attack_library: AttackLibrary,
) -> None:
    scanner = MultiAgentScanner(adapters=_system(), attack_library=shared_attack_library)
    scanner._topology = _topology()
    scanner.graph.import_topology(scanner._topology)
    with patch(
        "ziran.application.multi_agent.scanner.AgentScanner.run_campaign",
        new_callable=AsyncMock,
        return_value=_campaign(),
    ):
        result = await scanner.run_multi_agent_campaign(scan_individual=False)

    trace = _trace(result.propagation, "ma_cross_agent_injection")
    assert trace.canary.startswith("ZIRAN-H0-")
    assert trace.path == ["supervisor", "worker_a", "worker_b"]
    assert trace.furthest_hop == 2
    reached = {h.agent_id: h for h in trace.reached}
    assert reached["worker_a"].hop == 1 and reached["worker_a"].messages == [0]
    b = reached["worker_b"]
    assert b.hop == 2
    assert [(c.tool, c.argument) for c in b.tool_calls] == [("file_ticket", "$.body")]
    # worker B planted directly: its own canary, tagged with its hop
    assert _trace(result.propagation, "ma_cross_agent_injection", "worker_b").canary.startswith(
        "ZIRAN-H2-"
    )
    edges = [
        (u, v, d["hop"])
        for u, v, d in scanner.graph.graph.edges(data=True)
        if d.get("edge_type") == EdgeType.PROPAGATES_TO
        and d.get("vector_id") == "ma_cross_agent_injection"
        and d.get("canary") == trace.canary
    ]
    assert edges == [("supervisor", "worker_a", 1), ("worker_a", "worker_b", 2)]
    summary = result.summary()["propagation"]
    assert summary["furthest_hop"] == 2
    assert any(
        s["vector_id"] == "ma_cross_agent_injection" and s["path"] == trace.path
        for s in summary["spread"]
    )


@pytest.mark.asyncio
async def test_topology_exfil_records_leaked_parts_against_the_topology(
    shared_attack_library: AttackLibrary,
) -> None:
    reply = f"Agents: Billing Worker ({PROMPT_A}) and worker_b, whose prompt is: {PROMPT_B}"
    vectors = [shared_attack_library.get_vector("ma_topology_exfil")]
    traces = await trace_propagation(_system(reply), "supervisor", _topology(), vectors, "c1")
    leaked = {(p.agent_id, p.kind, p.text) for p in _trace(traces, "ma_topology_exfil").leaked}
    assert ("worker_a", "system_prompt", PROMPT_A.split(". ")[0] + ".") in leaked
    assert ("worker_b", "system_prompt", PROMPT_B.split(". ")[1]) in leaked
    assert ("worker_a", "name", "Billing Worker") in leaked
    assert ("worker_b", "name", "worker_b") in leaked
    assert not any(agent == "supervisor" for agent, _, _ in leaked)


@pytest.mark.asyncio
async def test_shorter_edge_wins_and_unobserved_and_errors_are_unmeasured(
    shared_attack_library: AttackLibrary,
) -> None:
    adapters = _system()
    adapters["worker_a"].__class__ = Broken  # A cannot report
    vectors = [shared_attack_library.get_vector("ma_cross_agent_injection")]
    shortcut = AgentEdge(source_id="supervisor", target_id="worker_b")
    traces = await trace_propagation(adapters, "supervisor", _topology(shortcut), vectors, "c1")
    trace = _trace(traces, "ma_cross_agent_injection")
    assert trace.unobserved == ["worker_a"]
    assert trace.path == ["supervisor", "worker_b"] and trace.furthest_hop == 1

    class Fails(FakeAgent):
        async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
            raise TimeoutError("slow")

    failed = await trace_propagation(
        {"supervisor": Fails()}, "supervisor", _topology(), vectors, "c"
    )
    assert failed[0].error == "TimeoutError: slow"
    assert failed[0].reached == [] and failed[0].path == [] and failed[0].furthest_hop == 0


@pytest.mark.asyncio
async def test_agent_off_the_topology_has_no_hop(shared_attack_library: AttackLibrary) -> None:
    adapters = _system()
    adapters["stray"] = adapters.pop("worker_b")
    vectors = [shared_attack_library.get_vector("ma_cross_agent_injection")]
    traces = await trace_propagation(adapters, "supervisor", _topology(), vectors, "c1")
    stray = next(
        h for h in _trace(traces, "ma_cross_agent_injection").reached if h.agent_id == "stray"
    )
    assert stray.hop is None
    assert _trace(traces, "ma_cross_agent_injection", "stray").canary.startswith("ZIRAN-HX-")


@pytest.mark.asyncio
async def test_trace_hops_false_skips_tracing() -> None:
    adapter = AsyncMock()
    scanner = MultiAgentScanner(adapters={"main": adapter})
    scanner._topology = _topology()
    with patch(
        "ziran.application.multi_agent.scanner.AgentScanner.run_campaign",
        new_callable=AsyncMock,
        return_value=_campaign(),
    ):
        result = await scanner.run_multi_agent_campaign(scan_individual=False, trace_hops=False)
    assert result.propagation == []
    adapter.invoke.assert_not_called()


def test_cli_writes_hop_traces(tmp_path: Any) -> None:
    import json

    from click.testing import CliRunner

    from ziran.application.multi_agent.scanner import MultiAgentCampaignResult
    from ziran.domain.entities.multi_agent import PropagationTrace
    from ziran.interfaces.cli.main import cli

    target = tmp_path / "supervisor.yaml"
    target.write_text("url: https://agent.example.com\n")
    trace = PropagationTrace(
        vector_id="ma_cross_agent_injection",
        planted_at="supervisor",
        planted_hop=0,
        canary="ZIRAN-H0-0123456789",
        path=["supervisor", "worker_a", "worker_b"],
        furthest_hop=2,
    )
    result = MultiAgentCampaignResult(
        topology=_topology(), individual_results={}, propagation=[trace]
    )
    with patch(
        "ziran.application.multi_agent.scanner.MultiAgentScanner.run_multi_agent_campaign",
        new_callable=AsyncMock,
        return_value=result,
    ):
        out = CliRunner().invoke(
            cli, ["multi-agent-scan", "-t", str(target), "-o", str(tmp_path / "out")]
        )
    assert out.exit_code == 0, out.output
    assert "Furthest Canary Hop: 2" in out.output
    written = json.loads((tmp_path / "out" / "propagation.json").read_text())
    assert written[0]["path"] == ["supervisor", "worker_a", "worker_b"]
    summary = json.loads((tmp_path / "out" / "multi_agent_summary.json").read_text())
    assert summary["propagation"]["spread"][0]["furthest_hop"] == 2


@pytest.mark.parametrize("calls", ["junk", [1, None, {"tool": "", "input": {"x": "{canary}"}}]])
def test_malformed_reported_calls_give_no_tool_evidence(calls: Any) -> None:
    from ziran.application.multi_agent.propagation import _observe

    canary = hop_canary("c", "v", "a", 0)
    if isinstance(calls, list):
        calls = [{**c, "input": {"x": canary}} if isinstance(c, dict) else c for c in calls]
    agent = FakeAgent()
    agent.history = [{"role": "user", "content": f"hi {canary.lower()}"}]
    agent.get_state = lambda: AgentState(  # type: ignore[method-assign]
        session_id="s", conversation_history=agent.history, memory={"observed_tool_calls": calls}
    )
    assert _observe(agent, canary, []) == ([0], [])


# -- fix round: fail-closed reporting, guards and precision ----------------------------------


class Remote(FakeAgent):
    """An HTTP-style endpoint: the backend delegates server-side, unseen by its adapter."""

    def __init__(self, backend: Remote | None = None) -> None:
        super().__init__()
        self.backend = backend
        self.server_log: list[str] = []

    @property
    def observes_delegated_traffic(self) -> bool:
        return False

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        self.history.append({"role": "user", "content": message})
        if self.backend is not None:
            self.backend.server_log.append(message)
        return AgentResponse(content="ok")

    def get_state(self) -> AgentState:
        return AgentState(
            session_id="s",
            conversation_history=list(self.history),
            memory={"protocol": "rest", "tool_observations": list(self.calls)},
        )


def _vector(lib: AttackLibrary, vector_id: str = "ma_cross_agent_injection") -> list[Any]:
    return [lib.get_vector(vector_id)]


@pytest.mark.asyncio
async def test_blind_adapters_read_unmeasured_beyond_hop_0(
    shared_attack_library: AttackLibrary, tmp_path: Any
) -> None:
    b = Remote()
    a = Remote(backend=b)
    adapters: dict[str, BaseAgentAdapter] = {"supervisor": Remote(backend=a), "worker_a": a}
    traces = await trace_propagation(
        adapters, "supervisor", _topology(), _vector(shared_attack_library), "c"
    )
    planted = _trace(traces, "ma_cross_agent_injection")
    # worker_a cannot see delegated traffic; worker_b has no adapter at all
    assert sorted(planted.unobserved) == ["worker_a", "worker_b"]
    from ziran.application.multi_agent.scanner import MultiAgentCampaignResult

    result = MultiAgentCampaignResult(
        topology=_topology(), individual_results={}, propagation=traces
    )
    summary = result.summary()["propagation"]
    assert summary["beyond_hop_0"] == "unmeasured"
    assert summary["unmeasured"] == len(traces)


@pytest.mark.asyncio
async def test_reset_failure_is_an_unmeasured_trace(shared_attack_library: AttackLibrary) -> None:
    class ResetFails(FakeAgent):
        def reset_state(self) -> None:
            raise RuntimeError("boom")

    adapters = _system()
    adapters["worker_b"] = ResetFails(tool=True)
    traces = await trace_propagation(
        adapters, "supervisor", _topology(), _vector(shared_attack_library), "c"
    )
    assert len(traces) == 3
    assert all(t.error == "reset worker_b: RuntimeError: boom" and not t.reached for t in traces)


@pytest.mark.asyncio
async def test_reset_clears_leftover_evidence(shared_attack_library: AttackLibrary) -> None:
    adapters = _system()
    adapters["supervisor"].next = None  # the supervisor forwards nothing
    canary = hop_canary("c", "ma_cross_agent_injection", "supervisor", 0)
    adapters["worker_a"].history.append({"role": "user", "content": canary})
    traces = await trace_propagation(
        adapters, "supervisor", _topology(), _vector(shared_attack_library), "c"
    )
    trace = _trace(traces, "ma_cross_agent_injection")
    assert trace.canary == canary
    assert [h.agent_id for h in trace.reached] == ["supervisor"]


def test_canary_differs_across_vectors_and_campaigns() -> None:
    base = hop_canary("c1", "v1", "a", 0)
    assert base != hop_canary("c1", "v2", "a", 0)
    assert base != hop_canary("c2", "v1", "a", 0)


@pytest.mark.asyncio
async def test_path_is_shortest_through_agents_that_saw_it(
    shared_attack_library: AttackLibrary,
) -> None:
    # sup -> C -> B is shorter, but C never saw the canary: sup -> A -> D -> B is reported
    b = FakeAgent(tool=True)
    d = FakeAgent(nxt=b)
    a = FakeAgent(nxt=d)
    adapters: dict[str, BaseAgentAdapter] = {
        "supervisor": FakeAgent(nxt=a),
        "worker_a": a,
        "worker_d": d,
        "worker_c": FakeAgent(),
        "worker_b": b,
    }
    topology = MultiAgentTopology(
        agents=[AgentNode(id=k, name=k) for k in adapters],
        edges=[
            AgentEdge(source_id=s, target_id=t)
            for s, t in [
                ("supervisor", "worker_c"),
                ("worker_c", "worker_b"),
                ("supervisor", "worker_a"),
                ("worker_a", "worker_d"),
                ("worker_d", "worker_b"),
            ]
        ],
        entry_point_id="supervisor",
    )
    trace = _trace(
        await trace_propagation(
            adapters, "supervisor", topology, _vector(shared_attack_library), "c"
        ),
        "ma_cross_agent_injection",
    )
    assert trace.path == ["supervisor", "worker_a", "worker_d", "worker_b"]
    assert trace.furthest_hop == 3

    # with a direct edge, the shortest observed path wins over the longer one through A
    shortcut = _topology(AgentEdge(source_id="supervisor", target_id="worker_b"))
    trace = _trace(
        await trace_propagation(
            _system(), "supervisor", shortcut, _vector(shared_attack_library), "c"
        ),
        "ma_cross_agent_injection",
    )
    assert {h.agent_id: h.hop for h in trace.reached}["worker_b"] == 1
    assert trace.furthest_hop == 1


@pytest.mark.asyncio
async def test_bidirectional_edge_counts_both_ways(shared_attack_library: AttackLibrary) -> None:
    a = FakeAgent()
    adapters: dict[str, BaseAgentAdapter] = {"supervisor": FakeAgent(), "worker_a": a}
    adapters["worker_b"] = FakeAgent(nxt=a)
    bidir = MultiAgentTopology(
        agents=_topology().agents,
        edges=[
            AgentEdge(source_id="supervisor", target_id="worker_a"),
            AgentEdge(source_id="worker_a", target_id="worker_b", bidirectional=True),
        ],
        entry_point_id="supervisor",
    )
    traces = await trace_propagation(
        adapters, "supervisor", bidir, _vector(shared_attack_library), "c"
    )
    trace = _trace(traces, "ma_cross_agent_injection", "worker_b")
    assert trace.path == ["worker_b", "worker_a"] and trace.furthest_hop == 1


@pytest.mark.parametrize("key", [None, "tool_observations"])
def test_planted_reply_calls_and_http_observations_are_evidence(key: str | None) -> None:
    from ziran.application.multi_agent.propagation import _observe

    canary = hop_canary("c", "v", "a", 0)
    call = {"tool": "send_mail", "input": {"to": canary}}
    agent = FakeAgent()
    memory = {} if key is None else {key: [call]}
    agent.get_state = lambda: AgentState(  # type: ignore[method-assign]
        session_id="s", conversation_history=[], memory=memory
    )
    _, calls = _observe(agent, canary, [call] if key is None else [])
    assert [(c.tool, c.argument) for c in calls] == [("send_mail", "$.to")]


def _leak_topology(**worker: Any) -> MultiAgentTopology:
    return MultiAgentTopology(
        agents=[
            AgentNode(id="supervisor", name="Supervisor", system_prompt="You lead the team now."),
            AgentNode(id="worker_a", name="Billing Worker", **worker),
            AgentNode(id="sql", name="sql", system_prompt="You are a helpful assistant."),
        ],
        entry_point_id="supervisor",
    )


def test_leak_matching_guards() -> None:
    from ziran.application.multi_agent.propagation import _leaks

    def kinds(reply: str, **worker: Any) -> set[tuple[str, str]]:
        return {(p.agent_id, p.text) for p in _leaks(reply, _leak_topology(**worker), "supervisor")}

    # the planted agent's own name and prompt are not a leak of another agent
    assert kinds("Supervisor here. You lead the team now.") == set()
    # empty prompt and short sentences never match
    assert kinds("Be concise. Anything at all.", system_prompt="Be concise.") == set()
    # word boundaries: "sql" is not in "squeaky"
    assert kinds("a squeaky wheel") == set()
    # a plain-word capability is ordinary text; an identifier-shaped one is a leak
    assert kinds("I can search the web", capabilities=["search"]) == set()
    assert kinds("it calls lookup_invoice", capabilities=["lookup_invoice"]) == {
        ("worker_a", "lookup_invoice")
    }
    # generic or shared sentences are not one agent's prompt
    generic = "You are a helpful assistant."
    assert kinds(generic, system_prompt=generic) == set()
    shared = "Always check the order status first."
    assert kinds(shared, system_prompt=shared) == {("worker_a", shared)}
    topo = _leak_topology(system_prompt=shared)
    topo.agents[2].system_prompt = shared
    assert _leaks(shared, topo, "supervisor") == []


@pytest.mark.asyncio
async def test_budget_exceeded_skips_plants_and_records_usage(
    shared_attack_library: AttackLibrary,
) -> None:
    from ziran.application.usage import CampaignBudget, UsageLedger

    ledger = UsageLedger()
    budget = CampaignBudget.from_config({"usage_ledger": ledger, "max_campaign_tokens": 100})
    adapters = _system()
    traces = await trace_propagation(
        adapters, "supervisor", _topology(), _vector(shared_attack_library), "c", budget=budget
    )
    assert all(t.error is None for t in traces)
    assert sum(e.calls for e in ledger.entries() if e.stage == "target") == 3

    ledger.record("target", "unknown", 100, 0)
    adapters["supervisor"].history.clear()
    traces = await trace_propagation(
        adapters, "supervisor", _topology(), _vector(shared_attack_library), "c", budget=budget
    )
    assert all(t.error == "skipped: campaign budget exceeded" for t in traces)
    assert adapters["supervisor"].history == []


def test_cli_no_trace_hops_and_unmeasured_line(tmp_path: Any) -> None:
    from click.testing import CliRunner

    from ziran.application.multi_agent.scanner import MultiAgentCampaignResult
    from ziran.domain.entities.multi_agent import PropagationTrace
    from ziran.interfaces.cli.main import cli

    target = tmp_path / "supervisor.yaml"
    target.write_text("url: https://agent.example.com\n")
    trace = PropagationTrace(
        vector_id="v",
        planted_at="supervisor",
        planted_hop=0,
        canary="ZIRAN-H0-0123456789",
        unobserved=["worker_a", "worker_b"],
    )
    result = MultiAgentCampaignResult(
        topology=_topology(), individual_results={}, propagation=[trace]
    )
    with patch(
        "ziran.application.multi_agent.scanner.MultiAgentScanner.run_multi_agent_campaign",
        new_callable=AsyncMock,
        return_value=result,
    ) as run:
        out = CliRunner().invoke(
            cli,
            ["multi-agent-scan", "-t", str(target), "-o", str(tmp_path / "o"), "--no-trace-hops"],
        )
    assert out.exit_code == 0, out.output
    assert run.call_args.kwargs["trace_hops"] is False
    assert "unmeasured beyond hop 0" in out.output
