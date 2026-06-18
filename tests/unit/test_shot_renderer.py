"""Unit tests for the ShotRenderer (spec 023, T006)."""

from __future__ import annotations

import pytest

from ziran.application.attacks.many_shot import (
    MAX_SHOTS,
    ShotRenderer,
    clamp_shots,
    estimate_tokens,
)

pytestmark = pytest.mark.unit


def test_render_is_deterministic() -> None:
    r = ShotRenderer()
    assert r.render("cybercrime", 30) == r.render("cybercrime", 30)  # SC-006


def test_length_scales_with_n() -> None:
    r = ShotRenderer()
    assert len(r.render("fraud", 100)) > len(r.render("fraud", 10))  # FR-006


def test_render_stacks_n_shots() -> None:
    r = ShotRenderer()
    # Each shot block starts with "Q: " — count them.
    assert r.render("weapons", 7).count("Q: ") == 7


@pytest.mark.parametrize(
    "n,expected,clamped",
    [(0, 1, True), (-3, 1, True), (501, 500, True), (9999, MAX_SHOTS, True), (50, 50, False)],
)
def test_clamp(n: int, expected: int, clamped: bool) -> None:
    assert clamp_shots(n) == (expected, clamped)  # SC-003


def test_render_clamps_count() -> None:
    r = ShotRenderer()
    assert r.render("fraud", 0).count("Q: ") == 1  # clamped up to floor 1
    assert r.render("fraud", 99999).count("Q: ") == MAX_SHOTS  # clamped to max


def test_estimate_tokens() -> None:
    assert estimate_tokens("a" * 400) == 100


def test_unknown_key_raises() -> None:
    with pytest.raises(KeyError, match="unknown many-shot corpus key"):
        ShotRenderer().render("no_such_harm", 5)
