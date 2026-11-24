"""Every dangerous chain in the scan SARIF (spec 092)."""

from __future__ import annotations

import json
import time
from datetime import date
from typing import TYPE_CHECKING, Any

import pytest

from tests.conftest import MockAgentAdapter
from tests.unit.test_cicd_suppressions import _attack, _campaign, _chain, _entry
from tests.unit.test_trifecta import READER, _cap, _result, _scan_topology
from ziran.application.agent_scanner.structure_import import import_adapter_structure
from ziran.application.cicd.gate import QualityGate
from ziran.application.cicd.sarif import generate_sarif
from ziran.application.knowledge_graph.chain_analyzer import CHAIN_RULE_ID, ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.knowledge_graph.trifecta import DELEGATED_RULE_ID, RULE_ID
from ziran.domain.entities.ci import SuppressionFile

if TYPE_CHECKING:
    from ziran.domain.entities.phase import CampaignResult


def _rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = doc["runs"][0]["results"]
    return rows


def _rules(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}


def _gate(result: CampaignResult, *entries: Any) -> Any:
    return QualityGate().evaluate(result, SuppressionFile(version=1, entries=list(entries)))


@pytest.mark.unit
class TestChainRules:
    async def test_delegated_trifecta_under_its_own_rule(self) -> None:
        chains = await _scan_topology(READER, [("reader", "mailer")])
        doc = generate_sarif(_result([c.model_dump(mode="json") for c in chains]))
        (row,) = [r for r in _rows(doc) if r["ruleId"] == DELEGATED_RULE_ID]
        assert row["level"] == "error"
        assert row["properties"]["agent"] == "reader"
        assert row["properties"]["agents"] == ["reader", "mailer"]
        assert row["properties"]["tools"] == ["tool_read_inbox", "tool_send_email"]
        assert row["properties"]["vulnerability_type"] == "lethal_trifecta_delegated"
        assert "tool_send_email" in row["message"]["text"]
        rule = _rules(doc)[DELEGATED_RULE_ID]
        assert rule["properties"]["security-severity"] == "9.0"
        assert rule["fullDescription"]["text"] == (
            "An agent and the agents it delegates to read private data, "
            "see untrusted content and can send data out"
        )
        assert not [r for r in _rows(doc) if r["ruleId"] == RULE_ID]
        assert "suppressions" not in row

    @pytest.mark.parametrize(
        ("risk", "level"),
        [("critical", "error"), ("high", "error"), ("medium", "warning"), ("low", "note")],
    )
    def test_pair_chain_with_its_level(self, risk: str, level: str) -> None:
        doc = generate_sarif(_campaign(chains=[_chain(risk_level=risk)]))
        (row,) = _rows(doc)
        assert (row["ruleId"], row["level"]) == (CHAIN_RULE_ID, level)
        assert row["properties"] == {
            "tools": ["read_file", "http_request"],
            "vulnerability_type": "data_exfiltration",
            "severity": risk,
        }
        assert row["message"]["text"] == "data_exfiltration: read_file -> http_request"
        assert list(_rules(doc)) == [CHAIN_RULE_ID]

    def test_shared_rule_takes_the_highest_risk(self) -> None:
        chains = [_chain(risk_level="low"), _chain(("a", "b"), "high", "rce"), _chain(("c", "d"))]
        doc = generate_sarif(_campaign(chains=chains))
        assert [r["level"] for r in _rows(doc)] == ["note", "error", "error"]
        rule = _rules(doc)[CHAIN_RULE_ID]
        assert rule["defaultConfiguration"] == {"level": "error"}
        assert rule["properties"]["security-severity"] == "9.0"

    def test_a_lower_risk_after_a_higher_one_does_not_lower_the_rule(self) -> None:
        chains = [_chain(risk_level="critical"), _chain(("a", "b"), risk_level="low")]
        rule = _rules(generate_sarif(_campaign(chains=chains)))[CHAIN_RULE_ID]
        assert rule["defaultConfiguration"] == {"level": "error"}
        assert rule["properties"]["security-severity"] == "9.0"

    @pytest.mark.parametrize("risk", ["info", "", "severe"])
    def test_unknown_risk_is_a_warning(self, risk: str) -> None:
        doc = generate_sarif(_campaign(chains=[_chain(risk_level=risk)]))
        (row,) = _rows(doc)
        assert row["level"] == "warning"
        rule = _rules(doc)[CHAIN_RULE_ID]
        assert rule["defaultConfiguration"] == {"level": "warning"}
        assert rule["properties"]["security-severity"] == "5.0"

    def test_every_chain_has_its_own_fingerprint(self) -> None:
        trifecta = {
            "tools": ["x"],
            "risk_level": "critical",
            "vulnerability_type": "lethal_trifecta",
        }
        chains = [
            _chain(),
            _chain(("read_file", "send_email")),
            _chain(vulnerability_type="rce"),
            trifecta | {"evidence": {"agent": "a1"}},
            trifecta | {"evidence": {"agent": "a2"}},
        ]
        rows = _rows(generate_sarif(_campaign(chains=chains)))
        prints = [r["partialFingerprints"]["ziranChain/v1"] for r in rows]
        assert len(set(prints)) == len(chains)
        again = _rows(generate_sarif(_campaign(chains=chains)))
        assert prints == [r["partialFingerprints"]["ziranChain/v1"] for r in again]

    def test_hostile_tool_names_survive_json(self) -> None:
        name = 'x"\n::error::<b>'
        doc = generate_sarif(_campaign(chains=[_chain((name, "http_request"))]))
        (row,) = _rows(json.loads(json.dumps(doc)))
        assert row["properties"]["tools"][0] == name


@pytest.mark.unit
class TestChainSuppressions:
    def _two(self) -> CampaignResult:
        return _campaign(chains=[_chain(), _chain(("read_file", "send_email"))])

    def test_only_the_suppressed_chain_carries_suppressions(self) -> None:
        r = self._two()
        first = QualityGate._findings(r)[0]
        rows = _rows(generate_sarif(r, _gate(r, _entry(first))))
        assert rows[0]["suppressions"] == [{"kind": "external", "justification": "accepted risk"}]
        assert "suppressions" not in rows[1]

    def test_unmatched_or_expired_entry_suppresses_nothing(self) -> None:
        r = self._two()
        first = QualityGate._findings(r)[0]
        entries = [
            _entry(first, content_hash="0" * 64),
            _entry(first, expires=date(2000, 1, 1)),
        ]
        gate = _gate(r, *entries)
        assert not gate.passed
        assert all("suppressions" not in row for row in _rows(generate_sarif(r, gate)))

    def test_suppressed_attack_at_the_same_index_leaves_the_chain(self) -> None:
        r = _campaign(attacks=[_attack()], chains=[_chain()])
        attack = QualityGate._findings(r)[0]
        gate = _gate(r, _entry(attack))
        assert gate.suppressed_attacks() == {0: "accepted risk"}
        attack_row, chain_row = _rows(generate_sarif(r, gate))
        assert "suppressions" in attack_row
        assert chain_row["ruleId"] == CHAIN_RULE_ID and "suppressions" not in chain_row


@pytest.mark.unit
async def test_hundred_flat_tools_one_result_per_chain() -> None:
    caps = [_cap(f"{kind}_{i}") for kind in ("read_file", "http_request") for i in range(50)]
    graph = AttackKnowledgeGraph()
    for c in caps:
        graph.add_capability(c.id, c)
    await import_adapter_structure(MockAgentAdapter(), graph, caps)
    chains = [c.model_dump(mode="json") for c in ToolChainAnalyzer(graph).analyze()]
    result = _result(chains)
    start = time.perf_counter()
    doc = generate_sarif(result, QualityGate().evaluate(result))
    elapsed = time.perf_counter() - start
    rows = _rows(doc)
    assert len(chains) >= 2_500
    assert len(rows) == len(chains)
    assert elapsed < 2.0
    per_row = len(json.dumps(doc)) / len(rows)
    assert per_row < 1_000  # linear: each result costs a bounded few hundred bytes
