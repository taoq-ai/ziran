"""Unit tests for the ResultBuilder module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ziran.application.agent_scanner.result_builder import ResultBuilder, _compute_utility
from ziran.domain.entities.attack import TokenUsage


@pytest.mark.unit
class TestResultBuilderBuild:
    """Verify ResultBuilder.build assembles CampaignResult correctly."""

    @pytest.fixture
    def mock_graph(self) -> MagicMock:
        graph = MagicMock()
        graph.find_all_attack_paths.return_value = []
        graph.export_state.return_value = {
            "stats": {"nodes": 0, "edges": 0},
            "nodes": [],
            "edges": [],
        }
        return graph

    @pytest.fixture
    def builder(self, mock_graph: MagicMock) -> ResultBuilder:
        return ResultBuilder(graph=mock_graph, adapter_name="TestAdapter")

    def test_build_with_empty_phases(self, builder: ResultBuilder) -> None:
        """Campaign with no phases should produce a result with zero vulnerabilities."""
        with patch(
            "ziran.application.agent_scanner.result_builder.ToolChainAnalyzer"
        ) as mock_analyzer:
            mock_analyzer.return_value.analyze.return_value = []

            result, chains = builder.build(
                campaign_id="campaign_test_001",
                phase_results=[],
                attack_results=[],
                campaign_tokens=TokenUsage(),
                coverage_value="standard",
                max_concurrent_attacks=5,
                duration=1.0,
                capabilities_count=0,
            )

        assert result.campaign_id == "campaign_test_001"
        assert result.target_agent == "TestAdapter"
        assert result.total_vulnerabilities == 0
        assert result.final_trust_score == 0.0
        assert result.success is False
        assert result.phases_executed == []
        assert chains == []

    def test_build_with_phase_data(self, builder: ResultBuilder, mock_graph: MagicMock) -> None:
        """Campaign with phase results should aggregate vulnerabilities."""
        from ziran.domain.entities.phase import PhaseResult, ScanPhase

        phase_result = PhaseResult(
            phase=ScanPhase.VULNERABILITY_DISCOVERY,
            success=True,
            artifacts={},
            trust_score=0.7,
            discovered_capabilities=[],
            vulnerabilities_found=["vuln_1", "vuln_2"],
            graph_state=mock_graph.export_state(),
            duration_seconds=2.5,
            token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        )

        from ziran.domain.entities.attack import AttackCategory, AttackResult

        attack_results = [
            AttackResult(
                vector_id="vuln_1",
                vector_name="Test Vuln 1",
                category=AttackCategory.PROMPT_INJECTION,
                severity="high",
                successful=True,
                evidence={"note": "found"},
            ),
            AttackResult(
                vector_id="vuln_2",
                vector_name="Test Vuln 2",
                category=AttackCategory.DATA_EXFILTRATION,
                severity="medium",
                successful=True,
                evidence={"note": "found"},
            ),
        ]

        with patch(
            "ziran.application.agent_scanner.result_builder.ToolChainAnalyzer"
        ) as mock_analyzer:
            mock_analyzer.return_value.analyze.return_value = []

            result, _chains = builder.build(
                campaign_id="campaign_test_002",
                phase_results=[phase_result],
                attack_results=attack_results,
                campaign_tokens=TokenUsage(
                    prompt_tokens=100, completion_tokens=50, total_tokens=150
                ),
                coverage_value="comprehensive",
                max_concurrent_attacks=10,
                duration=5.0,
                capabilities_count=3,
            )

        assert result.total_vulnerabilities == 2
        assert result.final_trust_score == 0.7
        assert result.success is True
        assert len(result.phases_executed) == 1
        assert result.coverage_level == "comprehensive"
        assert result.token_usage["total_tokens"] == 150

    def test_build_metadata_fields(self, builder: ResultBuilder) -> None:
        """Metadata should contain expected keys."""
        with patch(
            "ziran.application.agent_scanner.result_builder.ToolChainAnalyzer"
        ) as mock_analyzer:
            mock_analyzer.return_value.analyze.return_value = []

            result, _ = builder.build(
                campaign_id="campaign_test_003",
                phase_results=[],
                attack_results=[],
                campaign_tokens=TokenUsage(),
                coverage_value="standard",
                max_concurrent_attacks=5,
                duration=3.14,
                capabilities_count=2,
            )

        assert result.metadata["duration_seconds"] == 3.14
        assert result.metadata["capabilities_discovered"] == 2
        assert result.metadata["coverage_level"] == "standard"
        assert result.metadata["max_concurrent_attacks"] == 5
        assert result.metadata["attack_results_count"] == 0
        assert result.metadata["dangerous_chain_count"] == 0
        assert "graph_stats" in result.metadata

    def test_build_with_utility_scores(self, builder: ResultBuilder) -> None:
        """When baseline and post scores are provided, utility metrics appear in metadata."""
        with (
            patch(
                "ziran.application.agent_scanner.result_builder.ToolChainAnalyzer"
            ) as mock_analyzer,
            patch(
                "ziran.application.agent_scanner.result_builder._compute_utility"
            ) as mock_utility,
        ):
            mock_analyzer.return_value.analyze.return_value = []
            mock_utility.return_value = {"degradation": 0.1, "tasks_run": 5}

            result, _ = builder.build(
                campaign_id="campaign_test_004",
                phase_results=[],
                attack_results=[],
                campaign_tokens=TokenUsage(),
                coverage_value="standard",
                max_concurrent_attacks=5,
                duration=1.0,
                capabilities_count=0,
                baseline_score=0.9,
                baseline_results=[],
                post_score=0.8,
                post_results=[],
                utility_tasks_count=5,
            )

        assert "utility" in result.metadata
        mock_utility.assert_called_once_with(0.9, [], 0.8, [], 5)


@pytest.mark.unit
class TestComputeUtility:
    """Verify _compute_utility delegates correctly."""

    def test_delegates_to_utility_module(self) -> None:
        with patch("ziran.application.utility.measurer.compute_utility_metrics") as mock_fn:
            mock_fn.return_value = {"degradation": 0.05}

            result = _compute_utility(0.9, ["a"], 0.85, ["b"], 3)

            mock_fn.assert_called_once_with(0.9, ["a"], 0.85, ["b"], 3)
            assert result == {"degradation": 0.05}
