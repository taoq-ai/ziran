"""Unit tests for campaign checkpoint/resume support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from ziran.application.agent_scanner.checkpoint import (
    CampaignCheckpoint,
    CheckpointManager,
)


@pytest.fixture()
def tmp_output_dir(tmp_path: Path) -> Path:
    """Temporary output directory for checkpoint tests."""
    out = tmp_path / "ziran_results"
    out.mkdir()
    return out


def _sample_phase_result() -> dict[str, Any]:
    return {
        "phase": "reconnaissance",
        "success": True,
        "trust_score": 0.9,
        "duration_seconds": 5.0,
        "vulnerabilities_found": [],
        "artifacts": {},
        "graph_state": {},
        "error": None,
        "token_usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    }


def _sample_attack_result() -> dict[str, Any]:
    return {
        "vector_id": "v1",
        "vector_name": "test_vector",
        "category": "prompt_injection",
        "severity": "high",
        "successful": True,
        "evidence": {},
        "owasp_mapping": [],
        "business_impact": [],
        "token_usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.mark.unit
class TestCampaignCheckpoint:
    """Tests for the CampaignCheckpoint model."""

    def test_default_construction(self) -> None:
        ckpt = CampaignCheckpoint(campaign_id="test_001")
        assert ckpt.campaign_id == "test_001"
        assert ckpt.completed_phases == []
        assert ckpt.attack_results == []
        assert ckpt.tested_vector_ids == []
        assert ckpt.coverage == "standard"
        assert ckpt.checkpoint_time  # non-empty ISO string

    def test_full_construction(self) -> None:
        ckpt = CampaignCheckpoint(
            campaign_id="test_002",
            completed_phases=[_sample_phase_result()],
            attack_results=[_sample_attack_result()],
            tested_vector_ids=["v1", "v2"],
            token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            coverage="comprehensive",
            remaining_phases=["trust_building", "capability_mapping"],
        )
        assert len(ckpt.completed_phases) == 1
        assert ckpt.coverage == "comprehensive"
        assert len(ckpt.remaining_phases) == 2

    def test_serialization_roundtrip(self) -> None:
        ckpt = CampaignCheckpoint(
            campaign_id="test_003",
            completed_phases=[_sample_phase_result()],
            attack_results=[_sample_attack_result()],
            tested_vector_ids=["v1"],
        )
        data = ckpt.model_dump(mode="json")
        restored = CampaignCheckpoint.model_validate(data)
        assert restored.campaign_id == ckpt.campaign_id
        assert len(restored.completed_phases) == 1
        assert len(restored.attack_results) == 1


@pytest.mark.unit
class TestCheckpointManager:
    """Tests for the CheckpointManager."""

    def test_exists_returns_false_when_no_checkpoint(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        assert mgr.exists() is False

    def test_save_creates_checkpoint_file(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        ckpt = CampaignCheckpoint(campaign_id="save_test")
        path = mgr.save(ckpt)
        assert path.is_file()
        assert mgr.exists() is True

    def test_save_and_load_roundtrip(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        original = CampaignCheckpoint(
            campaign_id="roundtrip_test",
            completed_phases=[_sample_phase_result()],
            attack_results=[_sample_attack_result()],
            tested_vector_ids=["v1", "v2"],
            coverage="essential",
            remaining_phases=["exploitation", "exfiltration"],
        )
        mgr.save(original)
        loaded = mgr.load()
        assert loaded.campaign_id == original.campaign_id
        assert len(loaded.completed_phases) == 1
        assert len(loaded.attack_results) == 1
        assert loaded.tested_vector_ids == ["v1", "v2"]
        assert loaded.coverage == "essential"
        assert loaded.remaining_phases == ["exploitation", "exfiltration"]

    def test_load_raises_when_no_file(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        with pytest.raises(FileNotFoundError, match="No checkpoint file found"):
            mgr.load()

    def test_load_raises_on_invalid_json(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        mgr.path.write_text("not valid json {{}", encoding="utf-8")
        with pytest.raises(ValueError, match="Failed to load checkpoint"):
            mgr.load()

    def test_cleanup_removes_checkpoint(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        ckpt = CampaignCheckpoint(campaign_id="cleanup_test")
        mgr.save(ckpt)
        assert mgr.exists() is True
        mgr.cleanup()
        assert mgr.exists() is False

    def test_cleanup_noop_when_no_file(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        mgr.cleanup()  # Should not raise

    def test_save_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        mgr = CheckpointManager(tmp_path / "nonexistent" / "output")
        ckpt = CampaignCheckpoint(campaign_id="mkdir_test")
        path = mgr.save(ckpt)
        assert path.is_file()

    def test_atomic_write_no_corruption_on_valid_save(self, tmp_output_dir: Path) -> None:
        """Checkpoint should not leave a .tmp file after successful save."""
        mgr = CheckpointManager(tmp_output_dir)
        ckpt = CampaignCheckpoint(campaign_id="atomic_test")
        mgr.save(ckpt)
        tmp_files = list(tmp_output_dir.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_overwrite_existing_checkpoint(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        first = CampaignCheckpoint(
            campaign_id="overwrite_test",
            remaining_phases=["reconnaissance"],
        )
        mgr.save(first)

        second = CampaignCheckpoint(
            campaign_id="overwrite_test",
            completed_phases=[_sample_phase_result()],
            remaining_phases=[],
        )
        mgr.save(second)

        loaded = mgr.load()
        assert len(loaded.completed_phases) == 1
        assert loaded.remaining_phases == []


@pytest.mark.unit
class TestBuildCheckpoint:
    """Tests for CheckpointManager.build_checkpoint()."""

    def test_build_from_phase_results(self, tmp_output_dir: Path) -> None:
        from ziran.domain.entities.phase import PhaseResult

        mgr = CheckpointManager(tmp_output_dir)
        pr = PhaseResult.model_validate(_sample_phase_result())

        ckpt = mgr.build_checkpoint(
            campaign_id="build_test",
            phase_results=[pr],
            attack_results=[],
            tested_vector_ids={"v1", "v2"},
            token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            coverage="standard",
            remaining_phases=["trust_building"],
        )

        assert ckpt.campaign_id == "build_test"
        assert len(ckpt.completed_phases) == 1
        assert sorted(ckpt.tested_vector_ids) == ["v1", "v2"]
        assert ckpt.remaining_phases == ["trust_building"]

    def test_build_serialises_attack_results(self, tmp_output_dir: Path) -> None:
        from ziran.domain.entities.attack import AttackResult

        mgr = CheckpointManager(tmp_output_dir)
        ar = AttackResult.model_validate(_sample_attack_result())

        ckpt = mgr.build_checkpoint(
            campaign_id="ser_test",
            phase_results=[],
            attack_results=[ar],
            tested_vector_ids=set(),
            token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            coverage="standard",
            remaining_phases=[],
        )

        assert len(ckpt.attack_results) == 1
        assert ckpt.attack_results[0]["vector_id"] == "v1"

    def test_build_handles_dict_attack_results(self, tmp_output_dir: Path) -> None:
        mgr = CheckpointManager(tmp_output_dir)
        ar_dict = _sample_attack_result()

        ckpt = mgr.build_checkpoint(
            campaign_id="dict_test",
            phase_results=[],
            attack_results=[ar_dict],
            tested_vector_ids=set(),
            token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            coverage="standard",
            remaining_phases=[],
        )

        assert len(ckpt.attack_results) == 1
        assert ckpt.attack_results[0]["vector_id"] == "v1"
