"""Integration test: scanner writes checkpoints incrementally within a phase."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.checkpoint import (
    CampaignCheckpoint,
    CheckpointManager,
)
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.phase import ScanPhase

if TYPE_CHECKING:
    from pathlib import Path


class _CountingCheckpointManager(CheckpointManager):
    def __init__(self, output_dir: Path) -> None:
        super().__init__(output_dir)
        self.save_calls = 0

    def save(self, checkpoint: CampaignCheckpoint) -> Path:
        self.save_calls += 1
        return super().save(checkpoint)


@pytest.mark.integration
class TestScannerIncrementalCheckpoint:
    async def test_saves_within_phase_not_only_between(self, tmp_path: Path) -> None:
        adapter = MockAgentAdapter(
            responses=["I cannot help with that request."],
            capabilities=[],
        )
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
        mgr = _CountingCheckpointManager(tmp_path)

        await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            checkpoint_manager=mgr,
            checkpoint_flush_interval=0.0,  # time bound always due -> flush every vector
        )

        # One phase -> the old between-phase code path saved exactly once.
        # Incremental flushing must produce more than one save.
        assert mgr.save_calls > 1
