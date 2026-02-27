"""Fixed campaign strategy — predetermined phase execution.

The ``FixedStrategy`` executes phases in the order they were provided,
with no adaptation or dynamic decision-making. This is the default
strategy and reproduces the original ``AgentScanner`` behaviour.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.strategies.protocol import (
    CampaignContext,
    CampaignStrategy,
    PhaseDecision,
)

if TYPE_CHECKING:
    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.phase import PhaseResult


class FixedStrategy:
    """Execute phases in a fixed, predetermined order.

    This is the default strategy — it simply iterates through the
    provided phase list without adaptation. Equivalent to the original
    ``AgentScanner.run_campaign()`` flow.

    Args:
        stop_on_critical: If True, stop when a critical vulnerability is found.
    """

    def __init__(self, *, stop_on_critical: bool = True) -> None:
        self._stop_on_critical = stop_on_critical

    def select_next_phase(self, context: CampaignContext) -> PhaseDecision | None:
        """Select the next unexecuted phase in order.

        Returns:
            Next phase decision, or None if all phases are done.
        """
        if not context.available_phases:
            return None

        next_phase = context.available_phases[0]
        return PhaseDecision(
            phase=next_phase,
            reasoning=f"Fixed order: executing {next_phase.value}",
        )

    def should_stop(self, context: CampaignContext) -> bool:
        """Stop if a critical vulnerability was found (if configured)."""
        if self._stop_on_critical and context.critical_found:
            return True
        return not context.available_phases

    def on_phase_complete(self, phase_result: PhaseResult, context: CampaignContext) -> None:
        """No-op — fixed strategy doesn't learn."""

    def prioritize_attacks(
        self,
        attacks: list[AttackVector],
        context: CampaignContext,
    ) -> list[AttackVector]:
        """Return attacks unchanged — no prioritization."""
        return attacks


# Verify protocol compliance at import time
assert isinstance(FixedStrategy(), CampaignStrategy)
