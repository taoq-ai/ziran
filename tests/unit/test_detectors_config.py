"""Unit tests for the .ziran/detectors.yaml threshold loader (spec 021, US2)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.infrastructure.config.detectors import (
    DetectorConfigError,
    load_detector_thresholds,
)

pytestmark = pytest.mark.unit


def test_missing_file_returns_defaults(tmp_path: Path) -> None:
    result = load_detector_thresholds(tmp_path / "absent.yaml")
    assert result == DetectorThresholds()


def test_empty_file_returns_defaults(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("", encoding="utf-8")
    assert load_detector_thresholds(cfg) == DetectorThresholds()


def test_partial_file_merges_with_defaults(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: 0.65\n", encoding="utf-8")
    result = load_detector_thresholds(cfg)
    assert result.hit == 0.65
    assert result.safe == 0.3


def test_out_of_range_value_raises_naming_field(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: 1.5\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError) as exc:
        load_detector_thresholds(cfg)
    assert "hit" in str(exc.value)


def test_hit_not_above_safe_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: 0.2\nsafe: 0.5\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError):
        load_detector_thresholds(cfg)


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: : :\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError):
        load_detector_thresholds(cfg)


def test_non_mapping_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("- 0.7\n- 0.3\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError):
        load_detector_thresholds(cfg)


def test_env_interpolation_supported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZIRAN_HIT", "0.66")
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: ${ZIRAN_HIT}\n", encoding="utf-8")
    result = load_detector_thresholds(cfg)
    assert result.hit == 0.66


# ── semantic block (spec 042) ─────────────────────────────────────────


def test_semantic_block_parsed(tmp_path: Path) -> None:
    from ziran.application.detectors.semantic import SemanticConfig

    cfg = tmp_path / "detectors.yaml"
    cfg.write_text(
        "semantic:\n  enabled: true\n  refusal_threshold: 0.7\n  margin: 0.1\n", encoding="utf-8"
    )
    t = load_detector_thresholds(cfg)
    assert t.semantic.enabled is True
    assert (t.semantic.refusal_threshold, t.semantic.margin) == (0.7, 0.1)
    assert t.semantic.success_threshold == SemanticConfig().success_threshold


@pytest.mark.parametrize("block", ["{bogus: 1}", "{refusal_threshold: 2}"])
def test_semantic_block_invalid_names_field(tmp_path: Path, block: str) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text(f"semantic: {block}\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError) as exc:
        load_detector_thresholds(cfg)
    assert "semantic." in str(exc.value)


def test_no_semantic_block_is_default(tmp_path: Path) -> None:
    from ziran.application.detectors.semantic import SemanticConfig

    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: 0.65\n", encoding="utf-8")
    assert load_detector_thresholds(cfg).semantic == SemanticConfig()
