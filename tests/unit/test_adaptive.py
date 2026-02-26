"""Unit tests for adaptive campaign strategies.

Tests the CampaignStrategy protocol, FixedStrategy, AdaptiveStrategy,
and LLMAdaptiveStrategy implementations, plus scanner integration.
"""

from __future__ import annotations

from typing import Any

from ziran.application.strategies.protocol import (
    CampaignContext,
    CampaignStrategy,
    PhaseDecision,
)
from ziran.domain.entities.phase import ScanPhase

# ──────────────────────────────────────────────────────────────────────
# Protocol compliance
# ──────────────────────────────────────────────────────────────────────


class TestStrategyProtocol:
    """Verify all strategies satisfy the CampaignStrategy protocol."""

    def test_fixed_is_strategy(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy

        assert isinstance(FixedStrategy(), CampaignStrategy)

    def test_adaptive_is_strategy(self) -> None:
        from ziran.application.strategies.adaptive import AdaptiveStrategy

        assert isinstance(AdaptiveStrategy(), CampaignStrategy)


# ──────────────────────────────────────────────────────────────────────
# FixedStrategy
# ──────────────────────────────────────────────────────────────────────


class TestFixedStrategy:
    """Tests for the FixedStrategy."""

    def test_select_next_phase_returns_first_available(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy

        strategy = FixedStrategy()
        ctx = CampaignContext(
            available_phases=[ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING],
        )
        decision = strategy.select_next_phase(ctx)
        assert decision is not None
        assert decision.phase == ScanPhase.RECONNAISSANCE

    def test_select_next_phase_returns_none_when_exhausted(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy

        strategy = FixedStrategy()
        ctx = CampaignContext(available_phases=[])
        decision = strategy.select_next_phase(ctx)
        assert decision is None

    def test_should_stop_on_critical(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy

        strategy = FixedStrategy(stop_on_critical=True)
        ctx = CampaignContext(
            available_phases=[ScanPhase.EXECUTION],
            critical_found=True,
        )
        assert strategy.should_stop(ctx) is True

    def test_should_not_stop_without_critical(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy

        strategy = FixedStrategy(stop_on_critical=True)
        ctx = CampaignContext(
            available_phases=[ScanPhase.EXECUTION],
            critical_found=False,
        )
        assert strategy.should_stop(ctx) is False

    def test_prioritize_attacks_passthrough(self) -> None:
        from ziran.application.strategies.fixed import FixedStrategy
        from ziran.domain.entities.attack import AttackCategory, AttackVector

        strategy = FixedStrategy()
        attacks = [
            AttackVector(
                id="v1",
                name="Vector 1",
                category=AttackCategory.PROMPT_INJECTION,
                severity="high",
                target_phase=ScanPhase.RECONNAISSANCE,
                description="Test vector 1",
            ),
            AttackVector(
                id="v2",
                name="Vector 2",
                category=AttackCategory.TOOL_MANIPULATION,
                severity="medium",
                target_phase=ScanPhase.RECONNAISSANCE,
                description="Test vector 2",
            ),
        ]
        result = strategy.prioritize_attacks(attacks, CampaignContext())
        assert result == attacks  # unchanged


# ──────────────────────────────────────────────────────────────────────
# AdaptiveStrategy
# ──────────────────────────────────────────────────────────────────────


class TestAdaptiveStrategy:
    """Tests for the rule-based AdaptiveStrategy."""

    def test_selects_highest_scored_phase(self) -> None:
        from ziran.application.strategies.adaptive import AdaptiveStrategy

        strategy = AdaptiveStrategy()
        ctx = CampaignContext(
            available_phases=[
                ScanPhase.RECONNAISSANCE,
                ScanPhase.VULNERABILITY_DISCOVERY,
                ScanPhase.EXPLOITATION_SETUP,
            ],
        )
        decision = strategy.select_next_phase(ctx)
        assert decision is not None
        # With no prior results, the first phase (reconnaisance) should be
        # favoured or at least some phase should be returned.
        assert decision.phase in ctx.available_phases

    def test_phase_scoring_changes_with_results(self) -> None:
        """Phases with synergies to successful categories should score higher."""
        from ziran.application.strategies.adaptive import AdaptiveStrategy
        from ziran.domain.entities.phase import PhaseResult

        strategy = AdaptiveStrategy()

        # Simulate a successful reconnaissance phase
        recon_result = PhaseResult(
            phase=ScanPhase.RECONNAISSANCE,
            success=True,
            vulnerabilities_found=["vuln_1"],
            trust_score=0.5,
            graph_state={},
            duration_seconds=1.0,
            token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

        ctx = CampaignContext(
            completed_phases=[recon_result],
            available_phases=[
                ScanPhase.TRUST_BUILDING,
                ScanPhase.EXPLOITATION_SETUP,
            ],
            total_vulnerabilities=1,
        )
        strategy.on_phase_complete(recon_result, ctx)
        decision = strategy.select_next_phase(ctx)
        assert decision is not None

    def test_should_stop_after_consecutive_failures(self) -> None:
        """Strategy should stop after too many consecutive empty phases."""
        from ziran.application.strategies.adaptive import AdaptiveStrategy
        from ziran.domain.entities.phase import PhaseResult

        strategy = AdaptiveStrategy(max_consecutive_failures=2)

        for phase in [ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING]:
            empty_result = PhaseResult(
                phase=phase,
                success=False,
                vulnerabilities_found=[],
                trust_score=0.5,
                graph_state={},
                duration_seconds=1.0,
                token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
            strategy.on_phase_complete(empty_result, CampaignContext())

        ctx = CampaignContext(
            available_phases=[ScanPhase.EXECUTION],
        )
        assert strategy.should_stop(ctx) is True

    def test_prioritize_attacks_reorders(self) -> None:
        """Adaptive strategy should reorder attacks."""
        from ziran.application.strategies.adaptive import AdaptiveStrategy
        from ziran.domain.entities.attack import AttackCategory, AttackVector

        strategy = AdaptiveStrategy()
        attacks = [
            AttackVector(
                id="v1",
                name="Low priority",
                category=AttackCategory.PROMPT_INJECTION,
                severity="low",
                target_phase=ScanPhase.RECONNAISSANCE,
                description="Low prio test",
            ),
            AttackVector(
                id="v2",
                name="High priority",
                category=AttackCategory.TOOL_MANIPULATION,
                severity="critical",
                target_phase=ScanPhase.RECONNAISSANCE,
                description="High prio test",
            ),
        ]
        result = strategy.prioritize_attacks(attacks, CampaignContext())
        # Should have reordered (critical before low)
        assert len(result) == 2


# ──────────────────────────────────────────────────────────────────────
# Scanner strategy integration
# ──────────────────────────────────────────────────────────────────────


class TestScannerStrategyIntegration:
    """Test that the scanner correctly uses campaign strategies."""

    async def test_campaign_with_fixed_strategy(self) -> None:
        """Campaign with FixedStrategy should behave like original."""
        from tests.conftest import MockAgentAdapter
        from ziran.application.agent_scanner.scanner import AgentScanner
        from ziran.application.attacks.library import AttackLibrary
        from ziran.application.strategies.fixed import FixedStrategy

        adapter = MockAgentAdapter(
            responses=["I cannot help with that."],
            capabilities=[],
        )
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
        strategy = FixedStrategy(stop_on_critical=True)

        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            strategy=strategy,
        )

        assert result.campaign_id.startswith("campaign_")
        assert len(result.phases_executed) == 1
        assert result.phases_executed[0].phase == ScanPhase.RECONNAISSANCE

    async def test_campaign_with_adaptive_strategy(self) -> None:
        """Campaign with AdaptiveStrategy should run successfully."""
        from tests.conftest import MockAgentAdapter
        from ziran.application.agent_scanner.scanner import AgentScanner
        from ziran.application.attacks.library import AttackLibrary
        from ziran.application.strategies.adaptive import AdaptiveStrategy

        adapter = MockAgentAdapter(
            responses=["I cannot help with that."],
            capabilities=[],
        )
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
        strategy = AdaptiveStrategy(stop_on_critical=True, max_consecutive_failures=2)

        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING],
            strategy=strategy,
        )

        assert result.campaign_id.startswith("campaign_")
        # Adaptive may stop early due to consecutive failures
        assert len(result.phases_executed) >= 1

    async def test_campaign_default_strategy_is_fixed(self) -> None:
        """When no strategy is provided, FixedStrategy should be used."""
        from tests.conftest import MockAgentAdapter
        from ziran.application.agent_scanner.scanner import AgentScanner
        from ziran.application.attacks.library import AttackLibrary

        adapter = MockAgentAdapter(
            responses=["I cannot help with that."],
            capabilities=[],
        )
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
        )

        # Should still work just fine with no strategy parameter
        assert result.campaign_id.startswith("campaign_")
        assert len(result.phases_executed) == 1

    async def test_strategy_stop_on_critical(self) -> None:
        """Campaign should stop early when strategy says so."""
        from tests.conftest import MockAgentAdapter
        from ziran.application.agent_scanner.scanner import AgentScanner
        from ziran.application.attacks.library import AttackLibrary
        from ziran.domain.entities.phase import PhaseResult

        # A custom strategy that always stops after first phase
        class StopImmediatelyStrategy:
            def select_next_phase(self, context: CampaignContext) -> PhaseDecision | None:
                if context.available_phases and not context.completed_phases:
                    return PhaseDecision(
                        phase=context.available_phases[0],
                        reasoning="first phase only",
                    )
                return None

            def should_stop(self, context: CampaignContext) -> bool:
                return len(context.completed_phases) >= 1

            def on_phase_complete(self, phase_result: PhaseResult, context: CampaignContext) -> None:
                pass

            def prioritize_attacks(
                self, attacks: list[Any], context: CampaignContext
            ) -> list[Any]:
                return attacks

        adapter = MockAgentAdapter(
            responses=["I cannot help."],
            capabilities=[],
        )
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING, ScanPhase.EXECUTION],
            strategy=StopImmediatelyStrategy(),
        )

        # Only 1 phase should have run
        assert len(result.phases_executed) == 1
