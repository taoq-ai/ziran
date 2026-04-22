"""Unit tests for compute_evasion_rate (spec 012 US5)."""

from __future__ import annotations

import pytest

from ziran.application.campaign.evasion import compute_evasion_rate
from ziran.domain.entities.attack import AttackCategory, AttackResult
from ziran.domain.entities.defence import DefenceDeclaration, DefenceProfile


def _result(
    vector_id: str,
    successful: bool,
    bypass_map: dict[str, bool] | None = None,
) -> AttackResult:
    evidence = {}
    if bypass_map is not None:
        evidence["defence_bypass"] = bypass_map
    return AttackResult(
        vector_id=vector_id,
        vector_name=vector_id,
        category=AttackCategory.PROMPT_INJECTION,
        severity="medium",
        successful=successful,
        evidence=evidence,
    )


class TestComputeEvasionRate:
    @pytest.mark.unit
    def test_returns_none_when_profile_is_none(self) -> None:
        findings = [_result("f1", True), _result("f2", False)]
        assert compute_evasion_rate(findings, None) is None

    @pytest.mark.unit
    def test_returns_none_when_profile_is_empty(self) -> None:
        findings = [_result("f1", True)]
        profile = DefenceProfile(name="empty")
        assert compute_evasion_rate(findings, profile) is None

    @pytest.mark.unit
    def test_returns_none_when_no_evaluable_defences(self) -> None:
        findings = [_result("f1", True), _result("f2", True)]
        profile = DefenceProfile(
            name="metadata-only",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="nemo", evaluable=False),
                DefenceDeclaration(kind="output_guard", identifier="lakera", evaluable=False),
            ],
        )
        assert compute_evasion_rate(findings, profile) is None

    @pytest.mark.unit
    def test_returns_zero_when_no_findings(self) -> None:
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="guard", evaluable=True),
            ],
        )
        assert compute_evasion_rate([], profile) == 0.0

    @pytest.mark.unit
    def test_returns_zero_when_no_successful_findings(self) -> None:
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="guard", evaluable=True),
            ],
        )
        findings = [_result("f1", False), _result("f2", False)]
        assert compute_evasion_rate(findings, profile) == 0.0

    @pytest.mark.unit
    def test_returns_zero_when_bypass_map_missing(self) -> None:
        # No evaluator has stamped per-finding bypass flags yet — the baseline
        # in this release (no built-in evaluators) yields zero.
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="guard", evaluable=True),
            ],
        )
        findings = [_result("f1", True), _result("f2", True)]
        assert compute_evasion_rate(findings, profile) == 0.0

    @pytest.mark.unit
    def test_returns_ratio_when_bypass_map_populated(self) -> None:
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="guard", evaluable=True),
            ],
        )
        findings = [
            _result("f1", True, bypass_map={"guard": True}),
            _result("f2", True, bypass_map={"guard": False}),
            _result("f3", True, bypass_map={"guard": True}),
        ]
        # 2 of 3 successful attacks bypassed → 0.6667
        assert compute_evasion_rate(findings, profile) == pytest.approx(0.6667, abs=1e-4)

    @pytest.mark.unit
    def test_only_successful_findings_count(self) -> None:
        profile = DefenceProfile(
            name="active",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="g", evaluable=True),
            ],
        )
        findings = [
            _result("f1", True, bypass_map={"g": True}),
            _result("f2", False, bypass_map={"g": True}),  # unsuccessful, excluded
        ]
        # Only f1 is in the denominator
        assert compute_evasion_rate(findings, profile) == 1.0

    @pytest.mark.unit
    def test_all_defences_must_be_bypassed(self) -> None:
        profile = DefenceProfile(
            name="layered",
            defences=[
                DefenceDeclaration(kind="input_filter", identifier="a", evaluable=True),
                DefenceDeclaration(kind="output_guard", identifier="b", evaluable=True),
            ],
        )
        findings = [
            _result("f1", True, bypass_map={"a": True, "b": True}),  # bypass
            _result("f2", True, bypass_map={"a": True, "b": False}),  # not bypass
        ]
        assert compute_evasion_rate(findings, profile) == 0.5
