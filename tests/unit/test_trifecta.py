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
