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


# ── LLM judge ensemble block (spec 041) ──────────────────────────────


def test_ensemble_block_loads(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text(
        "ensemble:\n"
        "  enabled: true\n"
        "  min_margin: 1\n"
        "  needs_review_below: 0.5\n"
        "  judges:\n"
        "    - name: primary\n"
        "    - name: strict\n"
        "      framing: Be strict.\n"
        "    - name: second\n"
        "      provider: litellm\n"
        "      model: m2\n",
        encoding="utf-8",
    )
    ensemble = load_detector_thresholds(cfg).ensemble
    assert ensemble.enabled is True
    assert ensemble.needs_review_below == 0.5
    assert [j.name for j in ensemble.judges] == ["primary", "strict", "second"]
    assert ensemble.judges[1].framing == "Be strict."
    assert ensemble.judges[2].model == "m2"


def test_invalid_ensemble_block_raises_with_path(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("ensemble:\n  enabled: true\n  judges:\n    - name: a\n", encoding="utf-8")
    with pytest.raises(DetectorConfigError) as exc:
        load_detector_thresholds(cfg)
    assert str(exc.value).startswith(str(cfg))
    assert "ensemble" in str(exc.value)


def test_flat_thresholds_keep_ensemble_disabled(tmp_path: Path) -> None:
    cfg = tmp_path / "detectors.yaml"
    cfg.write_text("hit: 0.65\n", encoding="utf-8")
    assert load_detector_thresholds(cfg).ensemble.enabled is False
