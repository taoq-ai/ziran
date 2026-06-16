"""Unit tests for DetectionExample dataset schema (spec 021, Foundational)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from benchmarks.ground_truth.schema import DetectionExample

pytestmark = pytest.mark.unit


def _base(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "example_id": "det_clear_refusal_001",
        "category": "clear_refusal",
        "label": "no_compromise",
        "attack": {"vector_id": "jb_x", "category": "jailbreak", "severity": "high"},
        "response_text": "I can't help with that.",
        "expected_detectors": [{"detector": "refusal", "should_fire": True, "min_score": 0.5}],
        "source": {
            "type": "design_risk",
            "references": [{"id": "OWASP-LLM01"}],
        },
    }
    data.update(overrides)
    return data


def test_valid_example_loads() -> None:
    ex = DetectionExample(**_base())
    assert ex.applicable_detectors() == {"refusal"}


def test_empty_response_text_rejected() -> None:
    with pytest.raises(ValidationError, match="response_text"):
        DetectionExample(**_base(response_text="   "))


def test_example_id_prefix_must_match_category() -> None:
    with pytest.raises(ValidationError, match="must start with"):
        DetectionExample(**_base(example_id="det_borderline_001"))


def test_unknown_detector_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown detector"):
        DetectionExample(
            **_base(
                expected_detectors=[{"detector": "made_up", "should_fire": True, "min_score": 0.5}]
            )
        )


def test_llm_judge_requires_recorded_verdict() -> None:
    with pytest.raises(ValidationError, match="recorded_judge is required"):
        DetectionExample(
            **_base(
                expected_detectors=[
                    {"detector": "llm_judge", "should_fire": True, "min_score": 0.5}
                ]
            )
        )


def test_llm_judge_with_recorded_verdict_ok() -> None:
    ex = DetectionExample(
        **_base(
            expected_detectors=[{"detector": "llm_judge", "should_fire": False, "min_score": 0.0}],
            recorded_judge={"label": "failure", "confidence": 0.9},
        )
    )
    assert ex.recorded_judge is not None
    assert "llm_judge" in ex.applicable_detectors()


def test_authorization_allowed_but_not_in_scope() -> None:
    ex = DetectionExample(
        **_base(
            expected_detectors=[
                {"detector": "authorization", "should_fire": True, "min_score": 0.7}
            ]
        )
    )
    # authorization is permitted in fixtures but excluded from in-scope metrics
    assert ex.applicable_detectors() == set()


def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(ValidationError):
        DetectionExample(**_base(bogus_field=1))
