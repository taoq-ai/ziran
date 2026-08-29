"""Campaign checkpoint/resume support for long-running scans.

Saves campaign state after each phase so interrupted campaigns can
be resumed from the last checkpoint.  The checkpoint file is written
to ``{output_dir}/.checkpoint.json`` and cleaned up automatically
on successful campaign completion.

Usage::

    # Saving (automatic — called by the scanner after each phase)
    mgr = CheckpointManager(output_dir)
    mgr.save(checkpoint)

    # Resuming
    mgr = CheckpointManager(output_dir)
    checkpoint = mgr.load()
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.entities.phase import PhaseResult
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from ziran.domain.entities.phase import ScanPhase

logger = get_logger(__name__)

_CHECKPOINT_FILENAME = ".checkpoint.json"

# Completion-count backstop for incremental flushes. The time bound is
# operator-tunable (``--checkpoint-flush-interval``); this count bound is a
# fixed weak knob so a burst of fast attacks still flushes periodically.
DEFAULT_FLUSH_EVERY_N_COMPLETIONS = 25
DEFAULT_FLUSH_INTERVAL_SECONDS = 10.0


class FlushThrottle:
    """Decides when to flush an incremental checkpoint.

    A flush is due after ``max_completions`` recorded completions OR after
    ``max_seconds`` have elapsed since the last flush, whichever comes first.
    This keeps mid-phase checkpoint writes off the per-vector hot path so the
    write overhead stays within budget.
    """

    def __init__(
        self,
        max_completions: int,
        max_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_completions = max(1, max_completions)
        self._max_seconds = max_seconds
        self._clock = clock
        self._count = 0
        self._last_flush = clock()

    def record(self) -> bool:
        """Record one completion; return ``True`` when a flush is due.

        Resets the counter and the elapsed timer when it returns ``True``.
        """
        self._count += 1
        due = (
            self._count >= self._max_completions
            or (self._clock() - self._last_flush) >= self._max_seconds
        )
        if due:
            self._count = 0
            self._last_flush = self._clock()
        return due


class CampaignCheckpoint(BaseModel):
    """Serialisable snapshot of an in-progress campaign."""

    campaign_id: str
    completed_phases: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Serialised PhaseResult dicts for completed phases",
    )
    attack_results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Serialised AttackResult dicts accumulated so far",
    )
    tested_vector_ids: list[str] = Field(
        default_factory=list,
        description="Vector IDs already tested (avoid re-running)",
    )
    token_usage: dict[str, int] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )
    coverage: str = "standard"
    remaining_phases: list[str] = Field(
        default_factory=list,
        description="Phase values still pending execution",
    )
    checkpoint_time: str = Field(
        default_factory=lambda: datetime.now(tz=UTC).isoformat(),
    )


class CheckpointManager:
    """Manages reading and writing checkpoint files on disk."""

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir
        self._path = output_dir / _CHECKPOINT_FILENAME

    @property
    def path(self) -> Path:
        """Path to the checkpoint file."""
        return self._path

    def exists(self) -> bool:
        """Return ``True`` if a checkpoint file exists."""
        return self._path.is_file()

    def save(self, checkpoint: CampaignCheckpoint) -> Path:
        """Atomically save a checkpoint to disk.

        Writes to a temporary file first to avoid corruption if the
        process is killed mid-write.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        try:
            data = checkpoint.model_dump(mode="json")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.replace(self._path)
            logger.debug("checkpoint_saved", path=str(self._path))
        except Exception:
            # Clean up temp file on failure
            tmp_path.unlink(missing_ok=True)
            raise
        return self._path

    def load(self) -> CampaignCheckpoint:
        """Load a checkpoint from disk.

        Raises:
            FileNotFoundError: If no checkpoint file exists.
            ValueError: If the checkpoint cannot be parsed.
        """
        if not self._path.is_file():
            msg = f"No checkpoint file found at {self._path}"
            raise FileNotFoundError(msg)

        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            return CampaignCheckpoint.model_validate(raw)
        except Exception as exc:
            msg = f"Failed to load checkpoint from {self._path}: {exc}"
            raise ValueError(msg) from exc

    def cleanup(self) -> None:
        """Remove the checkpoint file after a successful campaign."""
        if self._path.is_file():
            self._path.unlink()
            logger.debug("checkpoint_cleaned_up", path=str(self._path))

    def build_checkpoint(
        self,
        *,
        campaign_id: str,
        phase_results: list[PhaseResult],
        attack_results: list[Any],
        tested_vector_ids: set[str],
        token_usage: dict[str, int],
        coverage: str,
        remaining_phases: list[str],
    ) -> CampaignCheckpoint:
        """Build a checkpoint from the current campaign state."""
        serialised_attacks: list[dict[str, Any]] = []
        for ar in attack_results:
            if isinstance(ar, dict):
                serialised_attacks.append(ar)
            elif hasattr(ar, "model_dump"):
                serialised_attacks.append(ar.model_dump(mode="json"))
            else:
                serialised_attacks.append({"vector_id": str(ar)})

        return CampaignCheckpoint(
            campaign_id=campaign_id,
            completed_phases=[pr.model_dump(mode="json") for pr in phase_results],
            attack_results=serialised_attacks,
            tested_vector_ids=sorted(tested_vector_ids),
            token_usage=token_usage,
            coverage=coverage,
            remaining_phases=remaining_phases,
        )


class IncrementalCheckpointer:
    """Builds and atomically saves campaign checkpoints during a run.

    ``flush()`` is throttled and called from the per-vector hot path;
    ``write()`` forces a save at phase boundaries. Both read live campaign
    state through the references handed in at construction, so the scanner
    does not rebuild checkpoint arguments at each call site.
    """

    def __init__(
        self,
        manager: CheckpointManager,
        *,
        campaign_id: str,
        phase_results: list[PhaseResult],
        attack_results: list[Any],
        tested_vector_ids: set[str],
        remaining_phases: list[ScanPhase],
        coverage: str,
        token_provider: Callable[[], dict[str, int]],
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
    ) -> None:
        self._manager = manager
        self._campaign_id = campaign_id
        self._phase_results = phase_results
        self._attack_results = attack_results
        self._tested_vector_ids = tested_vector_ids
        self._remaining_phases = remaining_phases
        self._coverage = coverage
        self._token_provider = token_provider
        self._throttle = FlushThrottle(DEFAULT_FLUSH_EVERY_N_COMPLETIONS, flush_interval)

    def flush(self) -> None:
        """Save a checkpoint if the throttle says one is due (hot path)."""
        if self._throttle.record():
            self._write()

    def write(self) -> None:
        """Force a checkpoint save (phase boundary)."""
        self._write()

    def _write(self) -> None:
        self._manager.save(
            self._manager.build_checkpoint(
                campaign_id=self._campaign_id,
                phase_results=self._phase_results,
                attack_results=self._attack_results,
                tested_vector_ids=self._tested_vector_ids,
                token_usage=self._token_provider(),
                coverage=self._coverage,
                remaining_phases=[p.value for p in self._remaining_phases],
            )
        )


@dataclass
class ResumeState:
    """State reconstructed from a checkpoint when resuming a campaign."""

    campaign_id: str
    phase_results: list[PhaseResult]
    campaign_tokens: TokenUsage
    tested_vector_ids: set[str]
    attack_results: list[AttackResult]
    remaining_phases: list[ScanPhase]


def load_resume_state(manager: CheckpointManager, phases: list[ScanPhase]) -> ResumeState:
    """Load a checkpoint and derive the state needed to resume a campaign.

    Filters ``phases`` down to those not already completed; the interrupted
    phase (if any) stays in the list and re-enters, skipping tested vectors.
    """
    ckpt = manager.load()
    phase_results = [PhaseResult.model_validate(p) for p in ckpt.completed_phases]
    completed = {pr.phase for pr in phase_results}
    return ResumeState(
        campaign_id=ckpt.campaign_id,
        phase_results=phase_results,
        campaign_tokens=TokenUsage(
            prompt_tokens=ckpt.token_usage.get("prompt_tokens", 0),
            completion_tokens=ckpt.token_usage.get("completion_tokens", 0),
            total_tokens=ckpt.token_usage.get("total_tokens", 0),
        ),
        tested_vector_ids=set(ckpt.tested_vector_ids),
        attack_results=[AttackResult.model_validate(a) for a in ckpt.attack_results],
        remaining_phases=[p for p in phases if p not in completed],
    )
