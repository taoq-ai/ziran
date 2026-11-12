"""Unit tests: V2 role typing and the typed chains it adds (spec 066)."""

from __future__ import annotations

import re
from itertools import permutations

import pytest

from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.knowledge_graph.role_typing import (
    TYPED_VULNERABILITY_TYPES,
    tool_roles,
)
from ziran.domain.entities.capability import DangerousChain

pytestmark = pytest.mark.unit

READ, READ2, OUT, NOVERB = "lookup_ticket", "search_archive", "publish_bulletin", "acme_gateway"
EXFIL = re.compile("exfil|leak")  # the preregistration's exfiltration-class rule (section 4)


def _graph(tools: list[str]) -> AttackKnowledgeGraph:
    g = AttackKnowledgeGraph()
    for t in tools:
        g.add_tool(t)
    for a, b in permutations(tools, 2):
        g.add_tool_chain([a, b], risk_score=0.5)
    return g


def _typed(tools: list[str], **kw: object) -> list[DangerousChain]:
    found = ToolChainAnalyzer(_graph(tools), typed=True, **kw).analyze(include_cycles=False)  # type: ignore[arg-type]
    return [c for c in found if c.typed]


class TestToolRoles:
    def test_name_rules(self) -> None:
        assert tool_roles(READ) == {"source"}
        assert tool_roles(OUT) == {"egress"}
        assert tool_roles("run_shell_command") == {"exec"}
        assert tool_roles("delete_account") == {"high_impact"}
        assert tool_roles("transfer_funds") == {"egress", "high_impact"}
        assert tool_roles("fetchAndPost") == {"source", "egress"}
        assert tool_roles(NOVERB) == frozenset()
        assert tool_roles("reserve_hotel") == frozenset()  # a write verb outside V2
        assert tool_roles("") == frozenset()

    def test_table_names_are_typed_after_the_alias(self) -> None:
        assert tool_roles("Read") == {"source"}  # read_file
        assert tool_roles("Bash") == {"exec"}  # shell_execute
        assert tool_roles("WebFetch") == {"egress"}  # http_request

    def test_an_override_replaces_the_name_rules(self) -> None:
        assert tool_roles(NOVERB, frozenset({"egress"})) == {"egress"}
        assert tool_roles(READ, frozenset()) == frozenset()  # the reply says no role
        assert tool_roles("reserve_hotel", ["source", "high_impact"]) == {"source", "high_impact"}
        assert tool_roles(READ, None) == {"source"}  # unknown: the name rules stand

    @pytest.mark.parametrize("bad", [{"write"}, {"high"}, "egress", {""}, {None}])
    def test_an_override_outside_the_four_roles_is_refused(self, bad: object) -> None:
        with pytest.raises(ValueError, match="role"):
            tool_roles(READ, bad)  # type: ignore[arg-type]


class TestTypedChains:
    def test_typed_chains_are_off_by_default(self) -> None:
        assert ToolChainAnalyzer(_graph([READ, OUT])).analyze() == []
        with pytest.raises(ValueError, match="typed=True"):
            ToolChainAnalyzer(_graph([READ, OUT]), role_overrides={OUT: {"egress"}})

    def test_two_read_tools_give_no_typed_chain(self) -> None:
        assert _typed([READ, READ2]) == []

    def test_a_read_tool_and_an_outbound_tool_give_one(self) -> None:
        (chain,) = _typed([READ, OUT])
        assert chain.tools == [READ, OUT]
        assert chain.typed
        assert chain.vulnerability_type == "typed_data_exfiltration"
        assert chain.evidence["roles"] == {READ: ["source"], OUT: ["egress"]}
        assert chain.evidence["role_source"] == {READ: "name_rule", OUT: "name_rule"}

    def test_a_tool_with_no_verb_is_a_sink_only_with_the_override(self) -> None:
        assert _typed([READ, NOVERB]) == []
        (chain,) = _typed([READ, NOVERB], role_overrides={NOVERB: frozenset({"egress"})})
        assert chain.tools == [READ, NOVERB]
        assert chain.evidence["role_source"] == {READ: "name_rule", NOVERB: "override"}

    def test_an_override_can_remove_a_role(self) -> None:
        assert _typed([READ, OUT], role_overrides={OUT: frozenset()}) == []

    def test_one_chain_per_sink_role(self) -> None:
        types = {
            c.vulnerability_type for c in _typed([READ, "transfer_funds", "run_shell_command"])
        }
        assert types == set(TYPED_VULNERABILITY_TYPES.values())

    def test_only_the_egress_type_is_exfiltration_class(self) -> None:
        assert {t for t in TYPED_VULNERABILITY_TYPES.values() if EXFIL.search(t)} == {
            "typed_data_exfiltration"
        }
        assert TYPED_VULNERABILITY_TYPES["egress"] == "typed_data_exfiltration"

    def test_a_table_pair_is_not_typed_again(self) -> None:
        found = ToolChainAnalyzer(_graph(["read_file", "http_request"]), typed=True).analyze()
        assert {tuple(c.tools) for c in found if not c.typed} >= {("read_file", "http_request")}
        assert ("read_file", "http_request") not in {tuple(c.tools) for c in found if c.typed}

    def test_table_names_record_the_table(self) -> None:
        (chain,) = _typed(["Read", OUT])
        assert chain.evidence["role_source"] == {"Read": "table", OUT: "name_rule"}

    def test_a_bad_override_stops_the_analysis(self) -> None:
        with pytest.raises(ValueError, match="role"):
            _typed([READ, OUT], role_overrides={OUT: frozenset({"write"})})

    def test_chains_default_to_untyped(self) -> None:
        c = DangerousChain(
            tools=["a", "b"], risk_level="high", vulnerability_type="x", exploit_description=""
        )
        assert c.typed is False
        assert DangerousChain.model_validate(c.model_dump()).typed is False
