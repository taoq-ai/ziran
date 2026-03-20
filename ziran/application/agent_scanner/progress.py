"""Progress event types and emitter for campaign monitoring.

Provides the event model and a thin emitter helper used by the scanner
and phase/attack executors to report lifecycle events during a campaign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class ProgressEventType(StrEnum):
    """Types of progress events emitted during a campaign."""

    CAMPAIGN_START = "campaign_start"
    PHASE_START = "phase_start"
    PHASE_ATTACKS_LOADED = "phase_attacks_loaded"
    ATTACK_START = "attack_start"
    ATTACK_STREAMING = "attack_streaming"
    ATTACK_COMPLETE = "attack_complete"
    PHASE_COMPLETE = "phase_complete"
    CAMPAIGN_COMPLETE = "campaign_complete"


@dataclass
class ProgressEvent:
    """Progress event emitted during campaign execution.

    Provides enough information for callers to build progress bars,
    logging hooks, or real-time dashboards.

    Attributes:
        event: The type of progress event.
        phase: Current phase name (None for campaign-level events).
        phase_index: 0-based index of the current phase.
        total_phases: Total number of phases in the campaign.
        attack_index: 0-based index of the current attack within the phase.
        total_attacks: Total attacks in the current phase.
        attack_name: Human-readable name of the current attack vector.
        message: Optional human-readable description of the event.
    """

    event: ProgressEventType
    phase: str | None = None
    phase_index: int = 0
    total_phases: int = 0
    attack_index: int = 0
    total_attacks: int = 0
    attack_name: str = ""
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class ProgressEmitter:
    """Thin wrapper that fires :class:`ProgressEvent` instances.

    Centralises the ``if callback is not None`` guard so that callers
    can simply call ``emitter.emit(event)`` without checking.
    """

    def __init__(self, callback: Callable[[ProgressEvent], None] | None = None) -> None:
        self._callback = callback

    def emit(self, event: ProgressEvent) -> None:
        """Emit a progress event if a callback is registered."""
        if self._callback is not None:
            self._callback(event)

    @property
    def active(self) -> bool:
        """Return *True* when a callback is registered."""
        return self._callback is not None
