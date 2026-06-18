"""Unit tests for ManyShotConfig + AttackVector.many_shot (spec 023, T003)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ziran.domain.entities.attack import AttackVector, ManyShotConfig

pytestmark = pytest.mark.unit


def test_defaults() -> None:
    cfg = ManyShotConfig(corpus="cybercrime")
    assert cfg.n_shots == 50
    assert cfg.corpus == "cybercrime"


@pytest.mark.parametrize("bad", [0, -5, 501, 10_000])
def test_n_shots_out_of_range_rejected_at_load(bad: int) -> None:
    with pytest.raises(ValidationError):
        ManyShotConfig(corpus="fraud", n_shots=bad)


def test_attack_vector_many_shot_default_none() -> None:
    v = AttackVector(
        id="x",
        name="x",
        category="prompt_injection",
        target_phase="vulnerability_discovery",
        description="d",
        severity="high",
    )
    assert v.many_shot is None


def test_attack_vector_with_many_shot_roundtrips() -> None:
    v = AttackVector(
        id="x",
        name="x",
        category="prompt_injection",
        target_phase="vulnerability_discovery",
        description="d",
        severity="high",
        many_shot={"n_shots": 80, "corpus": "weapons"},
    )
    assert v.many_shot is not None
    assert v.many_shot.n_shots == 80
    assert v.many_shot.corpus == "weapons"
