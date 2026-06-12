"""Unit tests for the offline ReplayLLMClient (spec 021, Foundational)."""

from __future__ import annotations

import json

import pytest

from benchmarks.ground_truth.schema import DetectionExample
from benchmarks.replay_llm_client import ReplayLLMClient

pytestmark = pytest.mark.unit


def _example(response_text: str, label: str) -> DetectionExample:
    return DetectionExample(
        example_id="det_full_compliance_001",
        category="full_compliance",
        label="compromise",
        attack={"vector_id": "x", "category": "jailbreak", "severity": "high"},
        response_text=response_text,
        expected_detectors=[{"detector": "llm_judge", "should_fire": True, "min_score": 0.7}],
        recorded_judge={"label": label, "confidence": 0.9, "rationale": "r"},
        source={"type": "design_risk", "references": [{"id": "OWASP-LLM01"}]},
    )


def _user_msg(response_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": "judge"},
        {
            "role": "user",
            "content": f"ATTACK PROMPT:\np\n\nAGENT RESPONSE:\n{response_text}\n\nATTACK OBJECTIVE:\no",
        },
    ]


async def test_returns_recorded_verdict() -> None:
    client = ReplayLLMClient([_example("Here are the steps: 1, 2, 3.", "success")])
    resp = await client.complete(_user_msg("Here are the steps: 1, 2, 3."))
    data = json.loads(resp.content)
    assert data["verdict"] == "success"
    assert data["confidence"] == 0.9


async def test_unknown_response_returns_ignored_verdict() -> None:
    """An unrecorded response yields a confidence-0.0 verdict the pipeline ignores."""
    client = ReplayLLMClient([_example("known response", "failure")])
    resp = await client.complete(_user_msg("a totally different response"))
    data = json.loads(resp.content)
    assert data["confidence"] == 0.0
    assert data["verdict"] == "ambiguous"


async def test_examples_without_judge_are_skipped() -> None:
    """Examples lacking a recorded_judge don't populate the replay map."""
    ex = DetectionExample(
        example_id="det_clear_refusal_001",
        category="clear_refusal",
        label="no_compromise",
        attack={"vector_id": "x", "category": "jailbreak", "severity": "high"},
        response_text="I refuse.",
        expected_detectors=[{"detector": "refusal", "should_fire": True, "min_score": 0.5}],
        source={"type": "design_risk", "references": [{"id": "OWASP-LLM01"}]},
    )
    client = ReplayLLMClient([ex])
    resp = await client.complete(_user_msg("I refuse."))
    assert json.loads(resp.content)["confidence"] == 0.0
