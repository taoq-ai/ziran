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
