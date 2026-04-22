"""Campaign result construction extracted from AgentScanner.

Contains :class:`ResultBuilder` which assembles the final
:class:`CampaignResult` from phase results, graph analysis, and
optional utility measurements.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ziran.application.campaign.evasion import compute_evasion_rate
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.domain.entities.phase import CampaignResult, PhaseResult, compute_resilience

if TYPE_CHECKING:
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
    from ziran.domain.entities.attack import AttackResult, TokenUsage
    from ziran.domain.entities.defence import DefenceProfile

logger = logging.getLogger(__name__)


def _compute_utility(
    baseline_score: float,
    baseline_results: list[Any],
    post_score: float,
    post_results: list[Any],
    tasks_run: int,
) -> dict[str, Any]:
    """Build utility metrics dict for CampaignResult.metadata."""
    from ziran.application.utility.measurer import compute_utility_metrics

    return compute_utility_metrics(
        baseline_score, baseline_results, post_score, post_results, tasks_run
    )


class ResultBuilder:
    """Assembles a :class:`CampaignResult` from campaign execution data.

    Args:
        graph: Knowledge graph used during the campaign.
        adapter_name: Human-readable name of the target adapter.
    """

    def __init__(
        self,
        graph: AttackKnowledgeGraph,
        adapter_name: str,
    ) -> None:
        self._graph = graph
        self._adapter_name = adapter_name

    def build(
        self,
        *,
        campaign_id: str,
        phase_results: list[PhaseResult],
        attack_results: list[AttackResult],
        campaign_tokens: TokenUsage,
        coverage_value: str,
        max_concurrent_attacks: int,
        duration: float,
        capabilities_count: int,
        baseline_score: float | None = None,
        baseline_results: list[Any] | None = None,
        post_score: float | None = None,
        post_results: list[Any] | None = None,
        utility_tasks_count: int = 0,
        defence_profile: DefenceProfile | None = None,
    ) -> tuple[CampaignResult, list[Any]]:
        """Build the final campaign result.

        Returns:
            A tuple of ``(campaign_result, dangerous_chains)``.
        """
        # Analyze graph for attack paths
        critical_paths = self._graph.find_all_attack_paths()

        # Analyze tool chains for dangerous combinations
        chain_analyzer = ToolChainAnalyzer(self._graph)
        dangerous_chains = chain_analyzer.analyze()

        serialized_results = [r.model_dump(mode="json") for r in attack_results]

        metadata: dict[str, Any] = {
            "duration_seconds": duration,
            "capabilities_discovered": capabilities_count,
            "graph_stats": self._graph.export_state()["stats"],
            "attack_results_count": len(attack_results),
            "dangerous_chain_count": len(dangerous_chains),
            "coverage_level": coverage_value,
            "max_concurrent_attacks": max_concurrent_attacks,
        }

        if baseline_score is not None and post_score is not None:
            metadata["utility"] = _compute_utility(
                baseline_score,
                baseline_results or [],
                post_score,
                post_results or [],
                utility_tasks_count,
            )

        campaign_result = CampaignResult(
            campaign_id=campaign_id,
            target_agent=self._adapter_name,
            phases_executed=phase_results,
            total_vulnerabilities=sum(len(p.vulnerabilities_found) for p in phase_results),
            critical_paths=critical_paths,
            final_trust_score=phase_results[-1].trust_score if phase_results else 0.0,
            success=len(critical_paths) > 0 or any(p.vulnerabilities_found for p in phase_results),
            attack_results=serialized_results,
            dangerous_tool_chains=[c.model_dump(mode="json") for c in dangerous_chains],
            critical_chain_count=len([c for c in dangerous_chains if c.risk_level == "critical"]),
            token_usage={
                "prompt_tokens": campaign_tokens.prompt_tokens,
                "completion_tokens": campaign_tokens.completion_tokens,
                "total_tokens": campaign_tokens.total_tokens,
            },
            coverage_level=coverage_value,
            resilience=compute_resilience(serialized_results, phase_results),
            defence_profile=defence_profile,
            evasion_rate=compute_evasion_rate(attack_results, defence_profile),
            metadata=metadata,
        )

        return campaign_result, dangerous_chains
