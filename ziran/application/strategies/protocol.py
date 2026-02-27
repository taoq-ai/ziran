"""Campaign strategy protocol and base types.

Defines ``CampaignStrategy`` — the protocol that all campaign strategies
must implement. Strategies control the phase ordering, attack selection,
and early-termination decisions for scan campaigns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.phase import PhaseResult, ScanPhase


@dataclass
class PhaseDecision:
    """A strategy's decision for the next phase to execute.

    Returned by ``CampaignStrategy.select_next_phase()`` to tell the
    scanner which phase to run next and how to configure it.
    """

    phase: ScanPhase
    """The phase to execute next."""

    attack_filter: list[str] | None = None
    """Optional list of attack vector IDs to include (None = all)."""

    attack_boost: dict[str, float] = field(default_factory=dict)
    """Attack ID → priority boost multiplier (higher = run first)."""

    max_attacks: int | None = None
    """Optional cap on number of attacks to run in this phase."""

    reasoning: str = ""
    """Human-readable explanation of why this phase was selected."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Strategy-specific metadata."""


@dataclass
class CampaignContext:
    """Context passed to the strategy for decision-making.

    Accumulates campaign state so the strategy can make informed
    decisions about what to test next.
    """

    completed_phases: list[PhaseResult] = field(default_factory=list)
    """Results from previously completed phases."""

    available_phases: list[ScanPhase] = field(default_factory=list)
    """Phases that haven't been executed yet."""

    total_vulnerabilities: int = 0
    """Running count of vulnerabilities found so far."""

    critical_found: bool = False
    """Whether a critical vulnerability has been found."""

    attack_results_summary: dict[str, bool] = field(default_factory=dict)
    """Map of attack_id → successful (True/False) for all executed attacks."""

    discovered_capabilities: list[str] = field(default_factory=list)
    """Capabilities discovered during reconnaissance."""

    graph_state: dict[str, Any] = field(default_factory=dict)
    """Current knowledge graph state summary."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional context from the scanner."""


@runtime_checkable
class CampaignStrategy(Protocol):
    """Protocol for campaign execution strategies.

    Strategies control the dynamic flow of scan campaigns by deciding:
    - Which phase to execute next
    - Which attacks to prioritize within a phase
    - Whether the campaign should terminate early
    - How to adapt based on intermediate results

    Implementations range from fixed (predetermined phase order) to
    fully adaptive (LLM-driven reasoning about next steps).
    """

    def select_next_phase(self, context: CampaignContext) -> PhaseDecision | None:
        """Select the next phase to execute.

        Called by the scanner after each phase completes. Returns a
        ``PhaseDecision`` with the next phase and configuration, or
        ``None`` to terminate the campaign.

        Args:
            context: Current campaign context with all results so far.

        Returns:
            Phase decision, or None to stop the campaign.
        """
        ...

    def should_stop(self, context: CampaignContext) -> bool:
        """Determine if the campaign should stop early.

        Called after each phase. Allows the strategy to implement
        custom termination conditions beyond simple phase exhaustion.

        Args:
            context: Current campaign context.

        Returns:
            True if the campaign should terminate.
        """
        ...

    def on_phase_complete(self, phase_result: PhaseResult, context: CampaignContext) -> None:
        """Callback invoked after each phase completes.

        Allows the strategy to update internal state, learn from
        results, and adjust future decisions.

        Args:
            phase_result: Result of the just-completed phase.
            context: Updated campaign context.
        """
        ...

    def prioritize_attacks(
        self,
        attacks: list[AttackVector],
        context: CampaignContext,
    ) -> list[AttackVector]:
        """Reorder/filter attacks for the upcoming phase.

        Called before a phase executes its attacks. The strategy can
        reorder attacks by estimated effectiveness, filter out
        unlikely-to-succeed vectors, or inject dynamically generated attacks.

        Args:
            attacks: The attack vectors planned for the phase.
            context: Current campaign context.

        Returns:
            Reordered/filtered list of attacks to execute.
        """
        ...
