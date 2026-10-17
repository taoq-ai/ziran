"""Tests for the ChainPatternRegistry and YAML-driven pattern loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.chain_patterns import (
    ChainPattern,
    ChainPatternRegistry,
)
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

_YAML_PATH = (
    Path(__file__).resolve().parents[2]
    / "ziran"
    / "application"
    / "knowledge_graph"
    / "chain_patterns.yaml"
)


# ── Registry loading ─────────────────────────────────────────────────


class TestChainPatternRegistry:
    """Tests for loading and converting the pattern registry."""

    def test_default_loads_successfully(self) -> None:
        registry = ChainPatternRegistry.default()
        assert len(registry.patterns) > 0

    def test_minimum_pattern_count(self) -> None:
        """The built-in YAML must contain at least 100 patterns."""
        registry = ChainPatternRegistry.default()
        assert len(registry.patterns) >= 100

    def test_from_yaml_matches_default(self) -> None:
        registry = ChainPatternRegistry.from_yaml(_YAML_PATH)
        default = ChainPatternRegistry.default()
        assert len(registry.patterns) == len(default.patterns)

    def test_to_dangerous_patterns_keys_are_tuples(self) -> None:
        patterns = ChainPatternRegistry.default().to_dangerous_patterns()
        for key in patterns:
            assert isinstance(key, tuple)
            assert len(key) == 2
            assert isinstance(key[0], str)
            assert isinstance(key[1], str)

    def test_to_dangerous_patterns_values_have_required_fields(self) -> None:
        patterns = ChainPatternRegistry.default().to_dangerous_patterns()
        for (src, tgt), info in patterns.items():
            assert "type" in info, f"({src}, {tgt}) missing 'type'"
            assert "risk" in info, f"({src}, {tgt}) missing 'risk'"
            assert "description" in info, f"({src}, {tgt}) missing 'description'"
            assert info["risk"] in ("critical", "high", "medium", "low"), (
                f"({src}, {tgt}) has invalid risk: {info['risk']}"
            )

    def test_pattern_count_equals_dangerous_patterns_count(self) -> None:
        registry = ChainPatternRegistry.default()
        patterns = registry.to_dangerous_patterns()
        assert len(patterns) == len(registry.patterns)


# ── YAML validation ──────────────────────────────────────────────────


class TestChainPatternYAML:
    """Tests that the YAML file is well-formed and complete."""

    def test_all_patterns_have_category(self) -> None:
        registry = ChainPatternRegistry.default()
        for p in registry.patterns:
            assert p.category, f"Pattern ({p.source}, {p.target}) has empty category"

    def test_all_patterns_have_description(self) -> None:
        registry = ChainPatternRegistry.default()
        for p in registry.patterns:
            assert p.description, f"Pattern ({p.source}, {p.target}) has empty description"

    def test_no_duplicate_source_target_pairs(self) -> None:
        registry = ChainPatternRegistry.default()
        seen: set[tuple[str, str]] = set()
        for p in registry.patterns:
            key = (p.source, p.target)
            assert key not in seen, f"Duplicate pattern: {key}"
            seen.add(key)

    def test_covers_expected_categories(self) -> None:
        registry = ChainPatternRegistry.default()
        categories = {p.category for p in registry.patterns}
        expected = {
            "data_exfiltration",
            "code_execution",
            "privilege_escalation",
            "file_system",
            "command_injection",
            "authentication",
            "data_poisoning",
            "session_hijacking",
            "mcp_specific",
            "cloud_services",
            "framework_tools",
            "a2a_delegation",
            "memory_state",
            "cicd_pipeline",
            "browser_scraping",
            "crypto_wallet",
        }
        assert expected.issubset(categories), f"Missing categories: {expected - categories}"

    def test_risk_distribution(self) -> None:
        """Ensure a reasonable distribution of risk levels."""
        registry = ChainPatternRegistry.default()
        risks = [p.risk for p in registry.patterns]
        assert risks.count("critical") >= 30
        assert risks.count("high") >= 20


# ── Merge ────────────────────────────────────────────────────────────


class TestRegistryMerge:
    """Tests for merging two registries."""

    def test_merge_adds_new_patterns(self) -> None:
        base = ChainPatternRegistry(
            patterns=[
                ChainPattern(
                    source="a",
                    target="b",
                    type="test",
                    risk="low",
                    category="test",
                    description="test",
                )
            ]
        )
        other = ChainPatternRegistry(
            patterns=[
                ChainPattern(
                    source="c",
                    target="d",
                    type="test2",
                    risk="high",
                    category="test",
                    description="test2",
                )
            ]
        )
        merged = base.merge(other)
        assert len(merged.patterns) == 2

    def test_merge_overwrites_duplicates(self) -> None:
        base = ChainPatternRegistry(
            patterns=[
                ChainPattern(
                    source="a",
                    target="b",
                    type="original",
                    risk="low",
                    category="test",
                    description="original",
                )
            ]
        )
        other = ChainPatternRegistry(
            patterns=[
                ChainPattern(
                    source="a",
                    target="b",
                    type="override",
                    risk="high",
                    category="test",
                    description="override",
                )
            ]
        )
        merged = base.merge(other)
        assert len(merged.patterns) == 1
        assert merged.patterns[0].type == "override"
        assert merged.patterns[0].risk == "high"


# ── Error handling ───────────────────────────────────────────────────


class TestRegistryErrors:
    """Tests for error handling in the registry."""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ChainPatternRegistry.from_yaml(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_structure_raises(self, tmp_path: Path) -> None:
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("not_patterns: [1, 2, 3]")
        with pytest.raises(ValueError, match="top-level 'patterns' key"):
            ChainPatternRegistry.from_yaml(bad_yaml)


# ── Dev-split patterns (spec 058) ────────────────────────────────────


def _complete_graph(tools: list[str]) -> AttackKnowledgeGraph:
    """Every tool pair linked both ways, as the ground-truth runner builds agent graphs."""
    graph = AttackKnowledgeGraph()
    for tool in tools:
        graph.add_tool(tool)
    for a in tools:
        for b in tools:
            if a != b:
                graph.add_tool_chain([a, b], 0.5)
    return graph


def _direct_chains(tools: list[str]) -> dict[tuple[str, ...], str]:
    chains = ToolChainAnalyzer(_complete_graph(tools)).analyze(include_cycles=False)
    return {tuple(c.tools): c.vulnerability_type for c in chains}


@pytest.mark.unit
class TestDevSplitPatterns:
    """sql_query and python_repl to send_email, appended last (spec 058)."""

    @pytest.mark.parametrize(
        ("source", "vuln_type"),
        [("sql_query", "database_exfiltration"), ("python_repl", "repl_exfiltration")],
    )
    def test_pair_reports_exfiltration_without_cycles(self, source: str, vuln_type: str) -> None:
        assert _direct_chains([source, "send_email"]) == {(source, "send_email"): vuln_type}

    def test_appended_after_every_existing_pattern(self) -> None:
        last = [(p.source, p.target, p.type) for p in ChainPatternRegistry.default().patterns[-2:]]
        assert last == [
            ("sql_query", "send_email", "database_exfiltration"),
            ("python_repl", "send_email", "repl_exfiltration"),
        ]

    def test_existing_pairs_keep_their_type(self) -> None:
        """The data-analyst tool set gains two chains; read_file to send_email is unchanged."""
        found = _direct_chains(["sql_query", "python_repl", "send_email", "read_file"])
        assert found[("read_file", "send_email")] == "data_exfiltration"
        assert found[("sql_query", "send_email")] == "database_exfiltration"
        assert found[("python_repl", "send_email")] == "repl_exfiltration"
