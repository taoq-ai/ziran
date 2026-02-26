"""Adaptive campaign strategy — rule-based dynamic phase selection.

The ``AdaptiveStrategy`` makes intelligent decisions about which phase
to run next based on results from completed phases. It uses heuristic
rules to skip phases likely to be unproductive and prioritize attacks
with higher estimated success probability.

No LLM dependency — pure rule-based logic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ziran.application.strategies.protocol import (
    CampaignContext,
    CampaignStrategy,
    PhaseDecision,
)
from ziran.domain.entities.phase import ScanPhase

if TYPE_CHECKING:
    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.phase import PhaseResult

logger = logging.getLogger(__name__)

# Which categories tend to succeed after which phases
_PHASE_SYNERGIES: dict[ScanPhase, list[str]] = {
    ScanPhase.RECONNAISSANCE: [
        "system_prompt_extraction",
        "multi_agent",
    ],
    ScanPhase.TRUST_BUILDING: [
        "prompt_injection",
        "chain_of_thought_manipulation",
    ],
    ScanPhase.CAPABILITY_MAPPING: [
        "tool_manipulation",
        "privilege_escalation",
    ],
    ScanPhase.VULNERABILITY_DISCOVERY: [
        "indirect_injection",
        "data_exfiltration",
    ],
    ScanPhase.EXPLOITATION_SETUP: [
        "tool_manipulation",
        "privilege_escalation",
        "data_exfiltration",
    ],
    ScanPhase.EXECUTION: [
        "prompt_injection",
        "indirect_injection",
        "multi_agent",
    ],
    ScanPhase.PERSISTENCE: [
        "memory_poisoning",
    ],
    ScanPhase.EXFILTRATION: [
        "data_exfiltration",
    ],
}


class AdaptiveStrategy:
    """Rule-based adaptive campaign strategy.

    Adapts the campaign flow based on:
    - **Phase success rates**: Skip phases with categories similar to
      already-failed phases.
    - **Capability-aware targeting**: Prioritize attacks against
      discovered capabilities.
    - **Vulnerability chaining**: When a vulnerability is found,
      immediately try related exploitation phases.
    - **Early termination**: Stop when diminishing returns are detected.

    Example:
        ```python
        strategy = AdaptiveStrategy(stop_on_critical=True)
        scanner = AgentScanner(adapter=adapter, config={"strategy": strategy})
        ```
    """

    def __init__(
        self,
        *,
        stop_on_critical: bool = True,
        min_success_rate: float = 0.05,
        max_consecutive_failures: int = 3,
    ) -> None:
        """Initialize the adaptive strategy.

        Args:
            stop_on_critical: Stop on critical vulnerability.
            min_success_rate: Minimum attack success rate before skipping a phase.
            max_consecutive_failures: Skip remaining phases after this many
                consecutive zero-vulnerability phases.
        """
        self._stop_on_critical = stop_on_critical
        self._min_success_rate = min_success_rate
        self._max_consecutive_failures = max_consecutive_failures
        self._consecutive_failures = 0
        self._successful_categories: set[str] = set()
        self._failed_categories: set[str] = set()
        self._phase_history: list[tuple[ScanPhase, float]] = []

    def select_next_phase(self, context: CampaignContext) -> PhaseDecision | None:
        """Select the next phase based on accumulated results."""
        if not context.available_phases:
            return None

        # Score each available phase
        phase_scores: list[tuple[ScanPhase, float, str]] = []
        for phase in context.available_phases:
            score, reasoning = self._score_phase(phase, context)
            phase_scores.append((phase, score, reasoning))

        # Sort by score (highest first)
        phase_scores.sort(key=lambda x: x[1], reverse=True)

        best_phase, best_score, reasoning = phase_scores[0]

        # Skip if score is too low
        if best_score < 0.1 and self._consecutive_failures >= 2:
            logger.info("Adaptive strategy: skipping remaining phases (low scores)")
            return None

        logger.info(
            "Adaptive strategy: selected %s (score=%.2f, reason=%s)",
            best_phase.value,
            best_score,
            reasoning,
        )

        return PhaseDecision(
            phase=best_phase,
            reasoning=reasoning,
            metadata={"score": best_score, "all_scores": {p.value: s for p, s, _ in phase_scores}},
        )

    def should_stop(self, context: CampaignContext) -> bool:
        """Stop on critical finding or consecutive failures."""
        if self._stop_on_critical and context.critical_found:
            return True
        if self._consecutive_failures >= self._max_consecutive_failures:
            logger.info(
                "Adaptive strategy: stopping after %d consecutive failures",
                self._consecutive_failures,
            )
            return True
        return not context.available_phases

    def on_phase_complete(self, phase_result: PhaseResult, context: CampaignContext) -> None:
        """Update internal state based on phase results."""
        successful = len(phase_result.vulnerabilities_found)

        # Infer total attacks from context's attack results history
        # (the scanner populates attack_results_summary with all attack IDs)
        total = len(context.attack_results_summary) - sum(
            len(p.vulnerabilities_found) + len(p.artifacts)
            for p in context.completed_phases[:-1]
            if p != phase_result
        )
        rate = successful / max(total, 1)

        self._phase_history.append((phase_result.phase, rate))

        if successful > 0:
            self._consecutive_failures = 0
            # Track successful attack categories from phase artifacts
            for _vuln_id, details in phase_result.artifacts.items():
                if isinstance(details, dict) and details.get("category"):
                    self._successful_categories.add(details["category"])
        else:
            self._consecutive_failures += 1
            # Track failed categories from context
            for attack_id, was_successful in context.attack_results_summary.items():
                if not was_successful:
                    # We don't have category info here, but we track the ID
                    self._failed_categories.add(attack_id.split("_")[0])

    def prioritize_attacks(
        self,
        attacks: list[AttackVector],
        context: CampaignContext,
    ) -> list[AttackVector]:
        """Reorder attacks by estimated success probability."""

        def _attack_score(attack: AttackVector) -> float:
            score = 0.5  # Base score

            # Boost attacks in categories that have succeeded before
            if attack.category.value in self._successful_categories:
                score += 0.3

            # Penalize attacks in categories that have only failed
            pure_failures = self._failed_categories - self._successful_categories
            if attack.category.value in pure_failures:
                score -= 0.2

            # Boost critical/high severity
            if attack.severity == "critical":
                score += 0.2
            elif attack.severity == "high":
                score += 0.1

            # Boost if target capabilities have been discovered
            if context.discovered_capabilities:
                for cap in context.discovered_capabilities:
                    if cap.lower() in attack.name.lower():
                        score += 0.15

            return score

        return sorted(attacks, key=_attack_score, reverse=True)

    # ── Internal Scoring ─────────────────────────────────────────

    def _score_phase(self, phase: ScanPhase, context: CampaignContext) -> tuple[float, str]:
        """Score a phase based on the current campaign context.

        Returns:
            (score, reasoning) tuple.
        """
        score = 0.5  # Base score
        reasons: list[str] = []

        # Boost phases whose synergy categories have succeeded
        synergy_categories = _PHASE_SYNERGIES.get(phase, [])
        matching_successes = self._successful_categories & set(synergy_categories)
        if matching_successes:
            score += 0.3
            reasons.append(f"synergy with successful categories: {matching_successes}")

        # Penalize phases whose categories have only failed
        pure_failures = self._failed_categories - self._successful_categories
        matching_failures = pure_failures & set(synergy_categories)
        if matching_failures:
            score -= 0.2
            reasons.append(f"related categories have failed: {matching_failures}")

        # Boost exploitation phases if vulnerabilities were found
        if context.total_vulnerabilities > 0 and phase in (
            ScanPhase.EXPLOITATION_SETUP,
            ScanPhase.EXECUTION,
            ScanPhase.EXFILTRATION,
        ):
            score += 0.25
            reasons.append("vulnerabilities found — exploitation is promising")

        # Penalize late phases if no vulnerabilities found yet
        if context.total_vulnerabilities == 0 and phase in (
            ScanPhase.PERSISTENCE,
            ScanPhase.EXFILTRATION,
        ):
            score -= 0.3
            reasons.append("no vulns yet — late phases unlikely to succeed")

        # Boost recon/trust if early in the campaign
        if not context.completed_phases and phase in (
            ScanPhase.RECONNAISSANCE,
            ScanPhase.TRUST_BUILDING,
        ):
            score += 0.2
            reasons.append("early phases should run first")

        reasoning = "; ".join(reasons) if reasons else "default scoring"
        return max(0.0, min(1.0, score)), reasoning


# Verify protocol compliance at import time
assert isinstance(
    AdaptiveStrategy(),
    CampaignStrategy,
)
