"""Tests for the lethal trifecta check (spec 088)."""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.result_builder import ResultBuilder
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.agent_scanner.structure_import import import_adapter_structure
from ziran.application.cicd.gate import QualityGate
from ziran.application.cicd.sarif import generate_audit_sarif, generate_sarif
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType
from ziran.application.knowledge_graph.trifecta import RULE_ID, tool_legs
from ziran.application.static_analysis.claude_code_audit import audit_claude_code
from ziran.application.static_analysis.claude_code_baseline import (
    apply_baseline,
    build_baseline,
)
from ziran.domain.entities.attack import TokenUsage
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.ci import SuppressionEntry, SuppressionFile, chain_fingerprint
from ziran.domain.entities.claude_code import ClaudeCodeAgent, ClaudeCodeScan
from ziran.domain.entities.multi_agent import AgentEdge, AgentNode, MultiAgentTopology
from ziran.domain.entities.phase import CampaignResult, ScanPhase
from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path

SUPPORT = ["read_inbox", "get_customer", "send_email"]


def _agent(tools: str, name: str = "researcher") -> ClaudeCodeAgent:
    return ClaudeCodeAgent(
        name=name,
        tools=tools,
        file=f"agents/{name}.md",
        key_lines={"name": 2, "tools": 4},
        body_line=6,
    )


def _scan(*agents: ClaudeCodeAgent) -> ClaudeCodeScan:
    return ClaudeCodeScan(root=".", agents=list(agents), files_analyzed=len(agents))


def _lt(findings: list[Any]) -> list[Any]:
    return [f for f in findings if f.check_id == RULE_ID]


def _cap(name: str) -> AgentCapability:
    return AgentCapability(id=f"tool_{name}", name=name, type=CapabilityType.TOOL)


def _trifectas(chains: list[Any]) -> list[Any]:
    return [c for c in chains if c.vulnerability_type == "lethal_trifecta"]


def _flat(*tools: str, roles: dict[str, frozenset[str]] | None = None) -> list[Any]:
    graph = AttackKnowledgeGraph()
    for t in tools:
        graph.add_capability(t, _cap(t.removeprefix("tool_")))
    graph.add_co_resident_tools(tools)
    graph.trifecta_roles = roles or {}
    return _trifectas(ToolChainAnalyzer(graph).analyze())


@pytest.mark.unit
class TestToolLegs:
    @pytest.mark.parametrize(
        ("tool", "legs"),
        [
            ("Read", {"private_data"}),
            ("WebFetch", {"untrusted_content", "egress"}),
            ("read_inbox", {"untrusted_content", "private_data"}),
            ("get_customer", {"private_data"}),
            ("send_email", {"egress"}),
            ("read_email", {"untrusted_content", "private_data"}),
            ("fetch_customer", {"private_data"}),
            ("fetch_url", {"untrusted_content", "egress"}),
            ("WebSearch", {"untrusted_content"}),
            ("mcp__slack__slack_send_message", {"egress"}),
            ("Bash", set()),
            ("get_weather", set()),
            ("get_secret", {"private_data"}),
        ],
    )
    def test_name_rules(self, tool: str, legs: set[str]) -> None:
        assert tool_legs(tool) == legs

    def test_override_replaces_the_name_rules(self) -> None:
        assert tool_legs("send_email", []) == frozenset()

    @pytest.mark.parametrize("bad", ["egress", ["egress", "exec"]])
    def test_bad_override_raises(self, bad: Any) -> None:
        with pytest.raises(ValueError, match="trifecta override"):
            tool_legs("send_email", bad)


@pytest.mark.unit
class TestAudit:
    def test_researcher_is_flagged(self) -> None:
        (f,) = _lt(audit_claude_code(_scan(_agent("Read, WebFetch"))).findings)
        assert f.severity == "critical"
        assert f.tools == ("Read", "WebFetch")
        assert f.message == (
            "Agent 'researcher': lethal_trifecta: private data from Read; "
            "untrusted content from WebFetch; egress via WebFetch"
        )
        sarif = generate_audit_sarif([f])
        assert sarif["runs"][0]["results"][0]["ruleId"] == RULE_ID

    def test_support_agent_and_its_fix(self) -> None:
        assert len(_lt(audit_claude_code(_scan(_agent(", ".join(SUPPORT)))).findings)) == 1
        assert not _lt(audit_claude_code(_scan(_agent("read_inbox, get_customer"))).findings)

    @pytest.mark.parametrize(
        ("tools", "flagged"),
        [
            ("get_secret, WebFetch", True),
            ("WebFetch", False),  # no private data
            ("get_customer, send_email", False),  # no untrusted content
        ],
    )
    def test_each_leg_is_needed(self, tools: str, flagged: bool) -> None:
        assert bool(_lt(audit_claude_code(_scan(_agent(tools))).findings)) is flagged

    def test_string_override_raises(self) -> None:
        with pytest.raises(ValueError, match="trifecta override"):
            audit_claude_code(
                _scan(_agent("Read, WebFetch")), trifecta_roles={"WebFetch": "egress"}
            )

    def test_override_clears_it(self) -> None:
        report = audit_claude_code(
            _scan(_agent(", ".join(SUPPORT))), trifecta_roles={"send_email": []}
        )
        assert not _lt(report.findings)

    def test_baseline_accepts_it(self) -> None:
        scan = _scan(_agent("Read, WebFetch"))
        baseline = build_baseline(scan)
        assert "lethal_trifecta" in {
            c.vulnerability_type for c in baseline.agents["researcher"].chains
        }
        findings, narrowed = apply_baseline(audit_claude_code(scan).findings, scan, baseline)
        assert not [f for f in findings if f.check_id in (RULE_ID, "BL003")]
        assert narrowed == []

    def test_pair_baseline_does_not_accept_it(self) -> None:
        scan = _scan(_agent("Read, WebFetch"))
        baseline = build_baseline(scan)
        chains = baseline.agents["researcher"].chains
        baseline.agents["researcher"].chains = [
            c for c in chains if c.vulnerability_type != "lethal_trifecta"
        ]
        findings, _ = apply_baseline(audit_claude_code(scan).findings, scan, baseline)
        (bl,) = [f for f in findings if f.check_id == "BL003"]
        assert "lethal_trifecta" in bl.message


@pytest.mark.unit
class TestScan:
    async def _campaign(self, tools: list[str], roles: dict[str, Any] | None = None) -> Any:
        adapter = MockAgentAdapter(capabilities=[_cap(t) for t in tools])
        scanner = AgentScanner(adapter=adapter, config={})
        scanner.graph.trifecta_roles = roles or {}
        return await scanner.run_campaign(phases=[ScanPhase.RECONNAISSANCE])

    async def test_flat_support_agent(self) -> None:
        result = await self._campaign(SUPPORT)
        (chain,) = _trifectas_dicts(result)
        assert chain["risk_level"] == "critical"
        assert chain["chain_type"] == "trifecta"
        assert chain["evidence"] == {
            "private_data": ["tool_read_inbox", "tool_get_customer"],
            "untrusted_content": ["tool_read_inbox"],
            "egress": ["tool_send_email"],
        }
        sarif = generate_sarif(result)
        (row,) = sarif["runs"][0]["results"]
        assert (row["ruleId"], row["level"]) == (RULE_ID, "error")
        assert "agent" not in row["properties"] and "suppressions" not in row
        assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == {RULE_ID}

    async def test_suppressed_trifecta_is_suppressed_in_sarif(self) -> None:
        result = await self._campaign(SUPPORT)
        entries = [
            SuppressionEntry(
                fingerprint=f.fingerprint,
                content_hash=f.content_hash,
                reason="accepted risk",
                added_by="sec-team",
            )
            for f in QualityGate._findings(result)
        ]
        gate = QualityGate().evaluate(result, SuppressionFile(version=1, entries=entries))
        assert gate.passed
        (row,) = generate_sarif(result, gate)["runs"][0]["results"]
        assert row["suppressions"] == [{"kind": "external", "justification": "accepted risk"}]

    async def test_unmatched_or_expired_entry_leaves_it_unsuppressed(self) -> None:
        result = await self._campaign(SUPPORT)
        (finding,) = QualityGate._findings(result)
        entries = [
            SuppressionEntry(  # a pair chain over the same tools: another fingerprint
                fingerprint=chain_fingerprint(result.target_agent, "data_exfiltration"),
                content_hash=finding.content_hash,
                reason="pair only",
                added_by="sec-team",
            ),
            SuppressionEntry(
                fingerprint=finding.fingerprint,
                content_hash=finding.content_hash,
                reason="expired",
                added_by="sec-team",
                expires=date(2000, 1, 1),
            ),
        ]
        gate = QualityGate().evaluate(result, SuppressionFile(version=1, entries=entries))
        assert not gate.passed
        (row,) = generate_sarif(result, gate)["runs"][0]["results"]
        assert row["ruleId"] == RULE_ID and "suppressions" not in row

    async def test_suppressed_attack_does_not_suppress_the_trifecta(self) -> None:
        chains = (await self._campaign(SUPPORT)).dangerous_tool_chains
        attack = {
            "vector_id": "v1",
            "vector_name": "v1",
            "category": "prompt_injection",
            "severity": "low",
            "successful": True,
        }
        result = _result(chains).model_copy(update={"attack_results": [attack]})
        (attack_finding, _) = QualityGate._findings(result)
        entry = SuppressionEntry(
            fingerprint=attack_finding.fingerprint,
            content_hash=attack_finding.content_hash,
            reason="accepted risk",
            added_by="sec-team",
        )
        gate = QualityGate().evaluate(result, SuppressionFile(version=1, entries=[entry]))
        assert gate.suppressed_attacks() == {0: "accepted risk"}
        rows = generate_sarif(result, gate)["runs"][0]["results"]
        (lt,) = [r for r in rows if r["ruleId"] == RULE_ID]
        assert "suppressions" not in lt

    async def test_without_send_email(self) -> None:
        assert not _trifectas_dicts(await self._campaign(SUPPORT[:2]))

    async def test_override_removes_egress(self) -> None:
        result = await self._campaign(SUPPORT, {"send_email": frozenset()})
        assert not _trifectas_dicts(result)


def _result(chains: list[dict[str, Any]]) -> CampaignResult:
    from tests.unit.test_cli_main import _minimal_campaign_result

    return CampaignResult.model_validate(
        _minimal_campaign_result() | {"dangerous_tool_chains": chains}
    )


def _trifectas_dicts(result: CampaignResult) -> list[dict[str, Any]]:
    return [c for c in result.dangerous_tool_chains if c["vulnerability_type"] == "lethal_trifecta"]


@pytest.mark.unit
class TestScopes:
    def test_one_finding_per_graph_agent(self) -> None:
        graph = AttackKnowledgeGraph()
        for t in ["tool_read_inbox", "tool_send_email", "tool_get_weather"]:
            graph.add_capability(t, _cap(t.removeprefix("tool_")))
        for agent, tools in {
            "a1": ["tool_read_inbox", "tool_send_email"],
            "a2": ["tool_read_inbox", "tool_send_email"],
            "a3": ["tool_read_inbox", "tool_get_weather"],
        }.items():
            graph.add_agent_node(agent, role="worker")
            for t in tools:
                graph.add_edge(agent, t, EdgeType.USES_TOOL)
        graph.add_edge("a3", "tool_send_email", EdgeType.TRUSTS)  # not a tool the agent uses
        found = _trifectas(ToolChainAnalyzer(graph).analyze())
        assert sorted(c.evidence["agent"] for c in found) == ["a1", "a2"]
        sarif = generate_sarif(_result([c.model_dump(mode="json") for c in found]))
        assert sorted(r["properties"]["agent"] for r in sarif["runs"][0]["results"]) == ["a1", "a2"]

    def test_override_by_id_or_name(self) -> None:
        ids = [f"tool_{t}" for t in SUPPORT]
        assert len(_flat(*ids)) == 1
        assert not _flat(*ids, roles={"send_email": frozenset()})
        assert not _flat(*ids, roles={"tool_send_email": frozenset()})

    @pytest.mark.parametrize(("count", "name_len"), [(100, 100), (101, 100), (101, 20_000)])
    async def test_hostile_tool_lists_stay_linear(self, count: int, name_len: int) -> None:
        names = [f"read_inbox_{i}_{'x' * name_len}"[:name_len] for i in range(count)]
        caps = [_cap(n) for n in [*names, "send_email"]]
        graph = AttackKnowledgeGraph()
        for c in caps:
            graph.add_capability(c.id, c)
        await import_adapter_structure(MockAgentAdapter(), graph, caps)
        result, chains = ResultBuilder(graph, "flat").build(
            campaign_id="c",
            phase_results=[],
            attack_results=[],
            campaign_tokens=TokenUsage(),
            coverage_value="essential",
            max_concurrent_attacks=1,
            duration=0.0,
            capabilities_count=len(caps),
        )
        (chain,) = _trifectas(chains)
        assert chain.tools == [caps[0].id, caps[-1].id]
        assert len(chain.evidence["private_data"]) == count
        id_chars = sum(len(c.id) for c in caps)
        assert len(result.model_dump_json()) < 8 * id_chars + 500_000


@pytest.mark.unit
def test_cli_audit_reads_detectors_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "support.md").write_text(
        "---\nname: support\ndescription: d\ntools: read_inbox, get_customer, send_email\n---\nx\n"
    )
    monkeypatch.chdir(tmp_path)
    run = CliRunner().invoke(cli, ["audit", str(agents), "--format", "json"])
    assert '"LT001"' in run.output
    (tmp_path / ".ziran").mkdir()
    (tmp_path / ".ziran" / "detectors.yaml").write_text("trifecta_roles:\n  send_email: []\n")
    run = CliRunner().invoke(cli, ["audit", str(agents), "--format", "json"])
    assert '"LT001"' not in run.output
    (tmp_path / ".ziran" / "detectors.yaml").write_text("trifecta_roles:\n  send_email: [exec]\n")
    run = CliRunner().invoke(cli, ["audit", str(agents), "--format", "json"])
    assert "trifecta_roles not read" in run.stderr
    assert '"LT001"' in run.stdout


AUDIT_AGENT = (
    "---\nname: support\ndescription: d\ntools: read_inbox, get_customer, send_email\n---\nx\n"
)


@pytest.mark.unit
def test_cli_baseline_uses_the_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "support.md").write_text(AUDIT_AGENT)
    (tmp_path / ".ziran").mkdir()
    (tmp_path / ".ziran" / "detectors.yaml").write_text("trifecta_roles:\n  send_email: []\n")
    monkeypatch.chdir(tmp_path)
    b = tmp_path / "baseline.json"
    run = CliRunner().invoke(cli, ["audit", str(agents), "--write-baseline", str(b)])
    assert run.exit_code == 0, run.output
    assert "lethal_trifecta" not in b.read_text()
    run = CliRunner().invoke(cli, ["audit", str(agents), "--baseline", str(b), "--format", "json"])
    assert run.exit_code == 0, run.output
    assert '"BL003"' not in run.stdout and '"narrowed": []' in run.stdout


@pytest.mark.unit
def test_cli_scan_hands_the_override_to_the_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import MagicMock

    monkeypatch.chdir(tmp_path)
    (tmp_path / "agent.py").write_text("agent_executor = None\n")
    (tmp_path / ".ziran").mkdir()
    (tmp_path / ".ziran" / "detectors.yaml").write_text(
        "trifecta_roles:\n  send_email: []\n  lookup_order: [private_data, private_data]\n"
    )
    monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
    run = MagicMock()
    run.run.return_value = _result([])
    monkeypatch.setattr("ziran.interfaces.cli.main.asyncio", run)
    scanner_cls = MagicMock()
    monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", scanner_cls)
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    assert scanner_cls.return_value.graph.trifecta_roles == {
        "send_email": frozenset(),
        "lookup_order": frozenset({"private_data"}),
    }


@pytest.mark.unit
@pytest.mark.parametrize("kind", ["utf16", "directory"])
def test_cli_audit_survives_an_unreadable_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "support.md").write_text(AUDIT_AGENT)
    detectors = tmp_path / ".ziran" / "detectors.yaml"
    detectors.parent.mkdir()
    if kind == "directory":
        detectors.mkdir()
    else:
        detectors.write_text("trifecta_roles:\n  send_email: []\n", encoding="utf-16")
    monkeypatch.chdir(tmp_path)
    run = CliRunner().invoke(cli, ["audit", str(agents), "--format", "json"])
    assert run.exception is None or isinstance(run.exception, SystemExit)
    assert "trifecta_roles not read" in run.stderr
    assert '"LT001"' in run.stdout


# ── Slice 2: the delegated variant and ground truth ───────────────────


class _TopologyAdapter(MockAgentAdapter):
    def __init__(self, topology: MultiAgentTopology) -> None:
        super().__init__()
        self._topology = topology

    async def discover_structure(self) -> MultiAgentTopology | None:
        return self._topology


def _delegated(chains: list[Any]) -> list[Any]:
    return [c for c in chains if c.vulnerability_type == "lethal_trifecta_delegated"]


async def _scan_topology(agents: dict[str, list[str]], edges: list[tuple[str, str]]) -> list[Any]:
    """Chains of a scan whose adapter reports *agents* (id -> tool names) and *edges*."""
    names = list(dict.fromkeys(t for tools in agents.values() for t in tools))
    caps = [_cap(n) for n in names]
    topology = MultiAgentTopology(
        agents=[
            AgentNode(id=a, name=a, capabilities=[f"tool_{t}" for t in tools])
            for a, tools in agents.items()
        ],
        edges=[AgentEdge(source_id=s, target_id=t) for s, t in edges],
    )
    graph = AttackKnowledgeGraph()
    for c in caps:
        graph.add_capability(c.id, c)
    await import_adapter_structure(_TopologyAdapter(topology), graph, caps)
    return ToolChainAnalyzer(graph).analyze()


READER = {"reader": ["read_inbox", "get_customer"], "mailer": ["send_email"]}


@pytest.mark.unit
class TestDelegated:
    async def test_reader_delegating_to_mailer_is_flagged(self) -> None:
        chains = await _scan_topology(READER, [("reader", "mailer")])
        assert not _trifectas(chains)  # no single agent holds all three legs
        (chain,) = _delegated(chains)
        assert chain.evidence["agent"] == "reader"
        assert chain.evidence["agents"] == ["reader", "mailer"]
        assert chain.tools == ["tool_read_inbox", "tool_send_email"]
        assert chain.evidence["egress"] == ["tool_send_email"]
        assert chain.risk_level == "critical"

    async def test_direction_and_no_edge(self) -> None:
        assert not _delegated(await _scan_topology(READER, []))
        # the reader's results come back to a mailer that delegates to it
        (chain,) = _delegated(await _scan_topology(READER, [("mailer", "reader")]))
        assert chain.evidence["agents"] == ["mailer", "reader"]

    async def test_transitive_reach_and_cycles(self) -> None:
        agents = {"router": [], "reader": ["read_inbox"], "mailer": ["send_email"]}
        edges = [("router", "reader"), ("reader", "mailer"), ("mailer", "router")]
        found = {c.evidence["agent"]: c for c in _delegated(await _scan_topology(agents, edges))}
        # every agent in the cycle reaches all three legs
        assert sorted(found) == ["mailer", "reader", "router"]
        assert found["router"].evidence["agents"] == ["router", "reader", "mailer"]

    async def test_an_agent_holding_all_three_gets_the_plain_finding(self) -> None:
        agents = {"boss": ["get_weather"], "support": ["read_inbox", "send_email"]}
        chains = await _scan_topology(agents, [("boss", "support")])
        assert [c.evidence["agent"] for c in _trifectas(chains)] == ["support"]
        assert not _delegated(chains)

    def test_dangling_delegation_edge_is_ignored(self) -> None:
        graph = AttackKnowledgeGraph()
        for t in ["tool_read_inbox", "tool_send_email"]:
            graph.add_capability(t, _cap(t.removeprefix("tool_")))
        graph.add_agent_node("reader", role="worker")
        graph.add_edge("reader", "tool_read_inbox", EdgeType.USES_TOOL)
        # to a node that is no declared agent, and to a tool: neither joins the reader's reach
        graph.add_edge("reader", "ghost", EdgeType.DELEGATES_TO)
        graph.add_edge("reader", "tool_send_email", EdgeType.DELEGATES_TO)
        assert not _delegated(ToolChainAnalyzer(graph).analyze())

    async def test_gate_counts_it_and_suppresses_it_only_by_its_own_fingerprint(self) -> None:
        chains = await _scan_topology(READER, [("reader", "mailer")])
        result = _result([c.model_dump(mode="json") for c in chains])
        (finding,) = QualityGate._findings(result)
        assert finding.label == "lethal_trifecta_delegated" and finding.severity == "critical"

        def gate(vulnerability_type: str) -> bool:
            entry = SuppressionEntry(
                fingerprint=chain_fingerprint(result.target_agent, vulnerability_type),
                content_hash=finding.content_hash,
                reason="accepted",
                added_by="sec-team",
            )
            return (
                QualityGate().evaluate(result, SuppressionFile(version=1, entries=[entry])).passed
            )

        assert not gate("lethal_trifecta")  # the plain trifecta's entry does not cover it
        assert gate("lethal_trifecta_delegated")

    @pytest.mark.parametrize(("count", "name_len"), [(101, 100), (101, 20_000)])
    async def test_hostile_delegation_chain_stays_linear(self, count: int, name_len: int) -> None:
        agents = {f"a{i}": [f"read_inbox_{i}_{'x' * name_len}"[:name_len]] for i in range(count)}
        # every reader reaches one mailer with many long tools: no finding may copy them all
        agents["mailer"] = [f"send_email_{i}_{'x' * name_len}"[:name_len] for i in range(count)]
        edges = [(f"a{i}", f"a{i + 1}") for i in range(count - 1)] + [(f"a{count - 1}", "mailer")]
        found = _delegated(await _scan_topology(agents, edges))
        assert len(found) == count  # each reader reaches the mailer
        id_chars = sum(len(t) for tools in agents.values() for t in tools)
        size = sum(len(c.model_dump_json()) for c in found)
        assert all(len(c.evidence["agents"]) <= 4 and len(c.tools) <= 3 for c in found)
        assert size < 8 * id_chars + 500_000


@pytest.mark.unit
def test_ground_truth_support_agents() -> None:
    from benchmarks.ground_truth.run import (
        benchmark_chain_analyzer,
        benchmark_scenario_verdict,
        load_agents,
        load_scenarios,
    )

    agents = load_agents()
    scenarios = [s for s in load_scenarios() if s.scenario_id in {"gt_tc_tp_015", "gt_tc_tn_013"}]
    assert {s.agent_ref for s in scenarios} == {"vulnerable_support_inbox", "safe_support_inbox"}
    chain = benchmark_chain_analyzer(agents, scenarios)
    verdict = benchmark_scenario_verdict(agents, scenarios)
    assert (chain.tp, chain.fp, chain.fn) == (1, 0, 0)
    assert (verdict.tp, verdict.fp, verdict.fn) == (1, 0, 0)
