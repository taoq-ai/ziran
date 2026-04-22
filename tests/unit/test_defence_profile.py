"""Unit tests for DefenceProfile / DefenceDeclaration (spec 012 US5)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ziran.domain.entities.defence import DefenceDeclaration, DefenceProfile


class TestDefenceDeclaration:
    @pytest.mark.unit
    def test_accepts_valid_kind_and_identifier(self) -> None:
        d = DefenceDeclaration(kind="input_filter", identifier="nemo-guardrails@v0.8")
        assert d.kind == "input_filter"
        assert d.identifier == "nemo-guardrails@v0.8"
        assert d.evaluable is False

    @pytest.mark.unit
    def test_rejects_invalid_kind(self) -> None:
        with pytest.raises(ValidationError):
            DefenceDeclaration(kind="heuristic", identifier="x")  # type: ignore[arg-type]

    @pytest.mark.unit
    def test_rejects_empty_identifier(self) -> None:
        with pytest.raises(ValidationError):
            DefenceDeclaration(kind="output_guard", identifier="")

    @pytest.mark.unit
    def test_evaluable_defaults_false(self) -> None:
        d = DefenceDeclaration(kind="hybrid", identifier="custom-guard")
        assert d.evaluable is False

    @pytest.mark.unit
    def test_evaluable_respected_when_set(self) -> None:
        d = DefenceDeclaration(kind="hybrid", identifier="custom", evaluable=True)
        assert d.evaluable is True


class TestDefenceProfile:
    @pytest.mark.unit
    def test_empty_profile_is_empty(self) -> None:
        p = DefenceProfile(name="empty")
        assert p.is_empty
        assert p.evaluable_defences == []

    @pytest.mark.unit
    def test_profile_with_defences_reports_evaluable_subset(self) -> None:
        p = DefenceProfile(
            name="prod",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="a", evaluable=False),
                DefenceDeclaration(kind="output_guard", identifier="b", evaluable=True),
                DefenceDeclaration(kind="hybrid", identifier="c", evaluable=True),
            ],
        )
        assert not p.is_empty
        ids = [d.identifier for d in p.evaluable_defences]
        assert ids == ["b", "c"]

    @pytest.mark.unit
    def test_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            DefenceProfile(name="")

    @pytest.mark.unit
    def test_loads_from_dict(self) -> None:
        p = DefenceProfile.model_validate(
            {
                "name": "prod-ingress-v1",
                "defences": [
                    {
                        "kind": "input_filter",
                        "identifier": "nemo-guardrails@v0.8",
                    },
                ],
            }
        )
        assert p.name == "prod-ingress-v1"
        assert len(p.defences) == 1
        assert p.defences[0].evaluable is False

    @pytest.mark.unit
    def test_round_trips_through_model_dump(self) -> None:
        original = DefenceProfile(
            name="prod",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="a"),
            ],
        )
        restored = DefenceProfile.model_validate(original.model_dump())
        assert restored == original
