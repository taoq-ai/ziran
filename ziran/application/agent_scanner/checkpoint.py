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
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.phase import PhaseResult

logger = logging.getLogger(__name__)

_CHECKPOINT_FILENAME = ".checkpoint.json"


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
            logger.debug("Checkpoint saved to %s", self._path)
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
            logger.debug("Checkpoint cleaned up: %s", self._path)

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
