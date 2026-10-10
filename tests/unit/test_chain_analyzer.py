"""Tests for the ToolChainAnalyzer."""

from __future__ import annotations

import itertools
from unittest.mock import patch

import pytest

from ziran.application.knowledge_graph.chain_analyzer import (
    DANGEROUS_PATTERNS,
    ToolChainAnalyzer,
)
from ziran.application.knowledge_graph.graph import (
    AttackKnowledgeGraph,
    EdgeType,
    NodeType,
)
from ziran.domain.entities.capability import DangerousChain

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def empty_graph() -> AttackKnowledgeGraph:
    """A graph with no nodes."""
    return AttackKnowledgeGraph()


@pytest.fixture
def simple_graph() -> AttackKnowledgeGraph:
    """A graph with two tools connected by a dangerous pattern."""
    g = AttackKnowledgeGraph()
    g.add_tool("read_file", {"description": "Read local files"})
    g.add_tool("http_request", {"description": "Make HTTP requests"})
    g.add_edge("read_file", "http_request", edge_type=EdgeType.CAN_CHAIN_TO)
    return g


@pytest.fixture
def complex_graph() -> AttackKnowledgeGraph:
    """A graph with multiple dangerous chains."""
    g = AttackKnowledgeGraph()

    # Tools
    g.add_tool("read_file", {"description": "Read files"})
    g.add_tool("http_request", {"description": "HTTP requests"})
    g.add_tool("sql_query", {"description": "SQL queries"})
    g.add_tool("execute_code", {"description": "Execute code"})
    g.add_tool("write_file", {"description": "Write files"})
    g.add_tool("list_directory", {"description": "List dirs"})

    # Direct dangerous chains
    g.add_edge("read_file", "http_request", edge_type=EdgeType.CAN_CHAIN_TO)
    g.add_edge("sql_query", "execute_code", edge_type=EdgeType.CAN_CHAIN_TO)
    g.add_edge("read_file", "write_file", edge_type=EdgeType.CAN_CHAIN_TO)
    g.add_edge("list_directory", "read_file", edge_type=EdgeType.CAN_CHAIN_TO)

    return g


@pytest.fixture
def indirect_chain_graph() -> AttackKnowledgeGraph:
    """A graph where dangerous tools are connected indirectly."""
    g = AttackKnowledgeGraph()

    g.add_tool("read_file", {"description": "Read files"})
    g.add_tool("http_request", {"description": "HTTP requests"})

    # Intermediate node (not a direct edge between read_file and http_request)
    g.graph.add_node("data_transform", node_type=NodeType.CAPABILITY)
    g.add_edge("read_file", "data_transform", edge_type=EdgeType.LEADS_TO)
    g.add_edge("data_transform", "http_request", edge_type=EdgeType.LEADS_TO)

    return g


@pytest.fixture
def cycle_graph() -> AttackKnowledgeGraph:
    """A graph with a cycle involving dangerous tools."""
    g = AttackKnowledgeGraph()

    g.add_tool("read_file", {"description": "Read files"})
    g.add_tool("write_file", {"description": "Write files"})
    g.add_tool("http_request", {"description": "HTTP requests"})

    # Create a cycle: read_file → write_file → http_request → read_file
    g.add_edge("read_file", "write_file", edge_type=EdgeType.CAN_CHAIN_TO)
    g.add_edge("write_file", "http_request", edge_type=EdgeType.CAN_CHAIN_TO)
    g.add_edge("http_request", "read_file", edge_type=EdgeType.CAN_CHAIN_TO)

    return g


# ── Tests: analyze() ─────────────────────────────────────────────────


class TestToolChainAnalyzer:
    """Tests for the main analyze() method."""

    def test_empty_graph_returns_no_chains(self, empty_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(empty_graph)
        chains = analyzer.analyze()
        assert chains == []

    def test_simple_direct_chain_detected(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        chains = analyzer.analyze()

        assert len(chains) >= 1
        exfil_chains = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert len(exfil_chains) >= 1
        assert exfil_chains[0].risk_level == "critical"
        assert exfil_chains[0].tools == ["read_file", "http_request"]

    def test_multiple_chains_detected(self, complex_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(complex_graph)
        chains = analyzer.analyze()

        assert len(chains) >= 3

        types_found = {c.vulnerability_type for c in chains}
        assert "data_exfiltration" in types_found
        assert "sql_to_rce" in types_found

    def test_chains_sorted_by_risk_score(self, complex_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(complex_graph)
        chains = analyzer.analyze()

        scores = [c.risk_score for c in chains]
        assert scores == sorted(scores, reverse=True)

    def test_chains_deduplicated(self, simple_graph: AttackKnowledgeGraph) -> None:
        """Adding the same edge twice should not create duplicate chains."""
        simple_graph.add_edge("read_file", "http_request", edge_type=EdgeType.CAN_CHAIN_TO)
        analyzer = ToolChainAnalyzer(simple_graph)
        chains = analyzer.analyze()

        # Should have exactly one data_exfiltration chain
        exfil = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert len(exfil) == 1


# ── Tests: _find_direct_chains() ─────────────────────────────────────


class TestDirectChains:
    """Tests for direct (A→B) chain detection."""

    def test_direct_chain_found(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_direct_chains(tool_nodes, {})

        assert len(chains) >= 1
        assert chains[0].chain_type == "direct"
        assert chains[0].tools == ["read_file", "http_request"]

    def test_non_dangerous_edge_ignored(self) -> None:
        """An edge between non-matching tools should not produce a chain."""
        g = AttackKnowledgeGraph()
        g.add_tool("harmless_tool_a", {})
        g.add_tool("harmless_tool_b", {})
        g.add_edge("harmless_tool_a", "harmless_tool_b", edge_type=EdgeType.CAN_CHAIN_TO)

        analyzer = ToolChainAnalyzer(g)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_direct_chains(tool_nodes, {})
        assert chains == []

    def test_substring_matching(self) -> None:
        """tool IDs with prefixes should still match patterns."""
        g = AttackKnowledgeGraph()
        g.add_tool("tool_read_file", {})
        g.add_tool("tool_http_request", {})
        g.add_edge("tool_read_file", "tool_http_request", edge_type=EdgeType.CAN_CHAIN_TO)

        analyzer = ToolChainAnalyzer(g)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_direct_chains(tool_nodes, {})
        assert len(chains) >= 1
        assert chains[0].vulnerability_type == "data_exfiltration"


# ── Tests: _find_indirect_chains() ───────────────────────────────────


class TestIndirectChains:
    """Tests for indirect (A→X→B) chain detection."""

    def test_indirect_chain_found(self, indirect_chain_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(indirect_chain_graph)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_indirect_chains(tool_nodes, {}, max_hops=3)

        assert len(chains) >= 1
        assert chains[0].chain_type == "indirect"
        assert "data_transform" in chains[0].graph_path

    def test_no_indirect_if_direct_exists(self, simple_graph: AttackKnowledgeGraph) -> None:
        """If there's a direct edge, indirect detection should skip it."""
        analyzer = ToolChainAnalyzer(simple_graph)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_indirect_chains(tool_nodes, {}, max_hops=3)
        # Direct edge exists, so indirect should not duplicate
        assert chains == []


# ── Tests: _find_chain_cycles() ──────────────────────────────────────


class TestChainCycles:
    """Tests for cycle detection."""

    def test_cycle_detected(self, cycle_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(cycle_graph)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_chain_cycles(tool_nodes, {})

        assert len(chains) >= 1
        cycle_chains = [c for c in chains if c.chain_type == "cycle"]
        assert len(cycle_chains) >= 1

    def test_no_cycles_in_acyclic_graph(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        tool_nodes = analyzer._get_tool_nodes()
        chains = analyzer._find_chain_cycles(tool_nodes, {})
        assert chains == []


# ── Tests: _calculate_risk_score() ───────────────────────────────────


class TestRiskScoring:
    """Tests for risk score calculation."""

    def test_critical_chain_scores_high(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        chain = DangerousChain(
            tools=["read_file", "http_request"],
            risk_level="critical",
            vulnerability_type="data_exfiltration",
            exploit_description="test",
            chain_type="direct",
        )
        import networkx as nx

        centrality = nx.betweenness_centrality(simple_graph.graph)
        score = analyzer._calculate_risk_score(chain, centrality)
        assert score >= 0.9

    def test_low_chain_scores_low(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        chain = DangerousChain(
            tools=["tool_a", "tool_b"],
            risk_level="low",
            vulnerability_type="info_disclosure",
            exploit_description="test",
            chain_type="indirect",
        )
        score = analyzer._calculate_risk_score(chain, {})
        assert score <= 0.5

    def test_score_between_zero_and_one(self, complex_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(complex_graph)
        chains = analyzer.analyze()
        for chain in chains:
            assert 0.0 <= chain.risk_score <= 1.0

    def test_direct_scores_higher_than_indirect(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        direct = DangerousChain(
            tools=["a", "b"],
            risk_level="high",
            vulnerability_type="test",
            exploit_description="test",
            chain_type="direct",
        )
        indirect = DangerousChain(
            tools=["a", "b"],
            risk_level="high",
            vulnerability_type="test",
            exploit_description="test",
            chain_type="indirect",
        )
        assert analyzer._calculate_risk_score(direct, {}) >= analyzer._calculate_risk_score(
            indirect, {}
        )

    def test_centrality_computed_once_during_analyze(
        self, complex_graph: AttackKnowledgeGraph
    ) -> None:
        """Betweenness centrality should be computed once, not per chain."""
        analyzer = ToolChainAnalyzer(complex_graph)
        with patch(
            "ziran.application.knowledge_graph.chain_analyzer.nx.betweenness_centrality",
            wraps=__import__("networkx").betweenness_centrality,
        ) as mock_bc:
            chains = analyzer.analyze()
            assert len(chains) >= 1
            assert mock_bc.call_count == 1


# ── Tests: _match_pattern() ──────────────────────────────────────────


class TestPatternMatching:
    """Tests for pattern substring matching."""

    def test_exact_match(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        result = analyzer._match_pattern("read_file", "http_request", {})
        assert result is not None
        assert result["type"] == "data_exfiltration"

    def test_prefix_match(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        result = analyzer._match_pattern("tool_read_file", "tool_http_request", {})
        assert result is not None

    def test_case_insensitive(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        result = analyzer._match_pattern("Read_File", "HTTP_REQUEST", {})
        assert result is not None

    def test_no_match(self, simple_graph: AttackKnowledgeGraph) -> None:
        analyzer = ToolChainAnalyzer(simple_graph)
        result = analyzer._match_pattern("harmless_a", "harmless_b", {})
        assert result is None


# ── Tests: Pattern database ──────────────────────────────────────────


class TestDangerousPatterns:
    """Tests for the pattern database itself."""

    def test_minimum_pattern_count(self) -> None:
        """We should have at least 100 patterns from YAML registry."""
        assert len(DANGEROUS_PATTERNS) >= 100

    def test_all_patterns_have_required_fields(self) -> None:
        for (src, tgt), info in DANGEROUS_PATTERNS.items():
            assert "type" in info, f"Pattern ({src}, {tgt}) missing 'type'"
            assert "risk" in info, f"Pattern ({src}, {tgt}) missing 'risk'"
            assert "description" in info, f"Pattern ({src}, {tgt}) missing 'description'"
            assert info["risk"] in ("critical", "high", "medium", "low"), (
                f"Pattern ({src}, {tgt}) has invalid risk: {info['risk']}"
            )

    def test_covers_key_vulnerability_types(self) -> None:
        """Ensure we cover the main vulnerability categories."""
        types = {info["type"] for info in DANGEROUS_PATTERNS.values()}
        expected = {
            "data_exfiltration",
            "sql_to_rce",
            "pii_leakage",
            "privilege_escalation",
            "file_manipulation",
            "directory_traversal",
            "cloud_data_exfiltration",
            "delegation_to_rce",
            "memory_exfiltration",
            "env_secret_exfiltration",
            "mcp_resource_exfiltration",
        }
        assert expected.issubset(types), f"Missing types: {expected - types}"


# ── Claude Code tool names (#417) ──────────────────────────────────────


def _cc_graph(tools: list[str], edges: list[tuple[str, str]]) -> AttackKnowledgeGraph:
    g = AttackKnowledgeGraph()
    for t in tools:
        g.add_tool(t)
    for a, b in edges:
        g.add_tool_chain([a, b], 0.5)
    return g


@pytest.mark.unit
class TestClaudeCodeToolNames:
    def _find(
        self, tools: list[str], edges: list[tuple[str, str]], expected: list[str]
    ) -> DangerousChain:
        chains = ToolChainAnalyzer(_cc_graph(tools, edges)).analyze()
        return next(c for c in chains if c.tools == expected)

    def test_read_webfetch_is_critical_exfiltration(self) -> None:
        chain = self._find(["Read", "WebFetch"], [("Read", "WebFetch")], ["Read", "WebFetch"])
        assert chain.risk_level == "critical"
        assert chain.vulnerability_type == "data_exfiltration"
        assert chain.graph_path == ["Read", "WebFetch"]

    def test_read_only_tools_produce_no_chain(self) -> None:
        tools = ["Read", "Grep", "Glob"]
        edges = [(a, b) for a in tools for b in tools if a != b]
        assert ToolChainAnalyzer(_cc_graph(tools, edges)).analyze() == []

    def test_read_mcp_send_is_critical_exfiltration(self) -> None:
        send = "mcp__slack__slack_send_message"
        chain = self._find(["Read", send], [("Read", send)], ["Read", send])
        assert chain.risk_level == "critical"
        assert chain.vulnerability_type == "data_exfiltration"

    def test_agent_bash_is_delegation_to_rce(self) -> None:
        chain = self._find(["Agent", "Bash"], [("Agent", "Bash")], ["Agent", "Bash"])
        assert chain.risk_level == "critical"
        assert chain.vulnerability_type == "delegation_to_rce"

    def test_read_git_push_is_code_exfiltration(self) -> None:
        push = "Bash(git push:*)"
        chain = self._find(["Read", push], [("Read", push)], ["Read", push])
        assert chain.risk_level == "critical"
        assert chain.vulnerability_type == "code_exfiltration"

    def test_secret_read_beats_generic_exfiltration(self) -> None:
        env, send = "Read(./.env)", "mcp__slack__slack_send_message"
        chain = self._find([env, send], [(env, send)], [env, send])
        assert chain.risk_level == "critical"
        assert chain.vulnerability_type == "secret_file_exfiltration"
        assert chain.graph_path == [env, send]


@pytest.mark.unit
class TestRagToolNames:
    """LangChain-style RAG tool names match existing patterns (spec 056)."""

    @pytest.mark.parametrize(
        ("source", "target", "vuln_type", "risk"),
        [
            ("tool_recursive_url_loader", "tool_execute_code", "remote_code_execution", "critical"),
            (
                "tool_recursive_url_loader",
                "tool_vector_store_write",
                "external_rag_poisoning",
                "high",
            ),
            ("tool_read_file", "tool_recursive_url_loader", "data_exfiltration", "critical"),
            ("tool_tavily_search", "tool_execute_code", "web_content_to_rce", "critical"),
            ("tool_vector_store_write", "tool_vector_store_query", "rag_poisoning", "high"),
        ],
    )
    def test_existing_pattern_fires(
        self, source: str, target: str, vuln_type: str, risk: str
    ) -> None:
        chains = ToolChainAnalyzer(_cc_graph([source, target], [(source, target)])).analyze()
        chain = next(c for c in chains if c.tools == [source, target])
        assert chain.vulnerability_type == vuln_type
        assert chain.risk_level == risk
        assert chain.graph_path == [source, target]

    @pytest.mark.parametrize(
        ("source", "target", "vuln_type", "risk"),
        [
            ("Agent", "shell_execute_tavily_search", "delegation_to_rce", "critical"),
            ("tool_read_file", "send_email_tavily_search", "data_exfiltration", "critical"),
            ("tool_read_file", "mcp__send_email__tavily_search", "data_exfiltration", "critical"),
        ],
    )
    def test_id_containing_a_name_keeps_its_chains(
        self, source: str, target: str, vuln_type: str, risk: str
    ) -> None:
        chains = ToolChainAnalyzer(_cc_graph([source, target], [(source, target)])).analyze()
        assert (vuln_type, risk) in {(c.vulnerability_type, c.risk_level) for c in chains}


@pytest.mark.unit
class TestUnrestrictedExecution:
    @pytest.mark.parametrize("tool", ["Bash", "Bash(*)"])
    def test_unscoped_bash_alone_is_flagged(self, tool: str) -> None:
        chains = ToolChainAnalyzer(_cc_graph([tool], [])).analyze()
        assert len(chains) == 1
        assert chains[0].tools == [tool]
        assert chains[0].vulnerability_type == "unrestricted_execution"
        assert chains[0].risk_level == "high"
        assert chains[0].chain_type == "direct"

    @pytest.mark.parametrize("tool", ["Bash(git push:*)", "Bash(npm test:*)"])
    def test_scoped_bash_is_not_flagged(self, tool: str) -> None:
        chains = ToolChainAnalyzer(_cc_graph([tool], [])).analyze()
        assert all(c.vulnerability_type != "unrestricted_execution" for c in chains)

    def test_read_only_tools_have_no_single_tool_finding(self) -> None:
        assert ToolChainAnalyzer(_cc_graph(["Read", "Grep", "Glob"], [])).analyze() == []


def _complete_graph(tools: list[str]) -> AttackKnowledgeGraph:
    return _cc_graph(tools, list(itertools.permutations(tools, 2)))


@pytest.mark.unit
class TestIncludeCycles:
    def test_cycles_off_on_complete_builtin_graph(self) -> None:
        tools = [
            "Agent",
            "Bash",
            "Edit",
            "Glob",
            "Grep",
            "NotebookEdit",
            "Read",
            "Skill",
            "TodoWrite",
            "WebFetch",
            "WebSearch",
            "Write",
        ]
        chains = ToolChainAnalyzer(_complete_graph(tools)).analyze(include_cycles=False)
        assert all(c.chain_type != "cycle" for c in chains)
        read_fetch = next(c for c in chains if c.tools == ["Read", "WebFetch"])
        assert read_fetch.risk_level == "critical"
        bash = next(c for c in chains if c.tools == ["Bash"])
        assert bash.vulnerability_type == "unrestricted_execution"

    def test_default_still_finds_cycles(self) -> None:
        tools = ["Read", "Grep", "WebFetch", "mcp__slack__send_message"]
        chains = ToolChainAnalyzer(_complete_graph(tools)).analyze()
        assert any(c.chain_type == "cycle" for c in chains)
