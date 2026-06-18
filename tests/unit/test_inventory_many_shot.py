"""Unit test: many-shot coverage tag in the inventory (spec 023, T018, FR-009)."""

from __future__ import annotations

import pytest

from benchmarks.inventory import collect_inventory

pytestmark = pytest.mark.unit


def test_inventory_surfaces_many_shot_tag() -> None:
    inv = collect_inventory()
    assert inv["tags"].get("many-shot", 0) >= 10  # the new vectors carry the tag
    assert len(inv["many_shot_vectors"]) >= 10
