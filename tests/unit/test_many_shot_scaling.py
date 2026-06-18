"""Unit tests for many-shot prompt scaling (spec 023, T013)."""

from __future__ import annotations

import pytest

from ziran.application.attacks.many_shot import ShotRenderer, estimate_tokens

pytestmark = pytest.mark.unit


def test_100_shots_exceeds_50k_tokens() -> None:
    r = ShotRenderer()
    prompt = r.render("cybercrime", 100)
    assert estimate_tokens(prompt) >= 50_000  # SC-002


def test_scales_with_count() -> None:
    r = ShotRenderer()
    assert estimate_tokens(r.render("fraud", 100)) > estimate_tokens(r.render("fraud", 10))


def test_clamp_keeps_count_bounded() -> None:
    r = ShotRenderer()
    # Over-range request is clamped to 500 (SC-003): not 0, not 9999.
    assert r.render("weapons", 9999).count("Q: ") == 500
