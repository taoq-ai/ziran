"""Unit tests for the configurable DetectorThresholds model (spec 021, US2)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ziran.application.detectors.thresholds import DetectorThresholds

pytestmark = pytest.mark.unit


def test_defaults_match_original_hardcoded_values() -> None:
    """Defaults MUST reproduce the original pipeline constants exactly (FR-007)."""
    t = DetectorThresholds()
    assert t.hit == 0.7
    assert t.safe == 0.3
    assert t.refusal_confidence == 0.5
    assert t.side_effect_override_confidence == 0.8
    assert t.side_effect_min_confidence == 0.7
    assert t.authorization_confidence == 0.6
    assert t.indicator_confidence == 0.5
    assert t.llm_judge_confidence == 0.6


def test_partial_override_keeps_other_defaults() -> None:
    t = DetectorThresholds(hit=0.65)
    assert t.hit == 0.65
    assert t.safe == 0.3  # untouched


@pytest.mark.parametrize("field", ["hit", "safe", "indicator_confidence"])
@pytest.mark.parametrize("bad", [-0.1, 1.5])
def test_out_of_range_rejected_naming_field(field: str, bad: float) -> None:
    with pytest.raises(ValidationError) as exc:
        DetectorThresholds(**{field: bad})
    assert field in str(exc.value)


def test_hit_must_exceed_safe() -> None:
    with pytest.raises(ValidationError) as exc:
        DetectorThresholds(hit=0.3, safe=0.3)
    assert "must be strictly greater" in str(exc.value)


def test_hit_below_safe_rejected() -> None:
    with pytest.raises(ValidationError):
        DetectorThresholds(hit=0.2, safe=0.5)


def test_unknown_key_rejected() -> None:
    with pytest.raises(ValidationError):
        DetectorThresholds(not_a_threshold=0.5)


def test_model_is_immutable() -> None:
    t = DetectorThresholds()
    with pytest.raises(ValidationError):
        t.hit = 0.9  # type: ignore[misc]
