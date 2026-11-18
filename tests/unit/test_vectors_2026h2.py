"""Unit tests for the 2026 H2 agent and MCP vectors (spec 076)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ziran.application.detectors.indicator import IndicatorDetector
from ziran.domain.entities.attack import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_TO_TACTIC,
    AtlasTactic,
    AtlasTechnique,
)
from ziran.domain.interfaces.adapter import AgentResponse

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary
    from ziran.domain.entities.attack import AttackVector

pytestmark = pytest.mark.unit

# Advisory -> family. Every source was published after 2026-06-18 (spec 076 table).
_SOURCES = {
    "GHSA-w794-rj3p-xv45": "mcp_config_command",
    "GHSA-2h4w-29cv-2cmv": "shell_allowlist_newline",
    "GHSA-7835-87q9-rgvv": "workspace_escape",
    "GHSA-5xjx-9qx6-jcrv": "workspace_escape",
    "GHSA-9fpm-3445-2vx4": "codegen_injection",
    "GHSA-7hgx-277f-7vmg": "tool_caller_policy",
    "GHSA-x5vx-c2c8-m3w9": "tool_caller_policy",
}


def _new_vectors(lib: AttackLibrary) -> list[AttackVector]:
    return [v for v in lib.vectors if "spec-076" in v.tags]


def _families(vector: AttackVector) -> set[str]:
    return {fam for ghsa, fam in _SOURCES.items() for ref in vector.references if ghsa in ref}


def test_at_least_six_vectors_over_four_families(shared_attack_library: AttackLibrary) -> None:
    vectors = _new_vectors(shared_attack_library)
    assert len(vectors) >= 6
    assert len(set().union(*(_families(v) for v in vectors))) >= 4


def test_each_vector_cites_a_dated_source_and_maps_taxonomies(
    shared_attack_library: AttackLibrary,
) -> None:
    for v in _new_vectors(shared_attack_library):
        assert _families(v), f"{v.id} cites no post-2026-06-18 advisory"
        assert v.owasp_mapping, v.id
        assert v.atlas_mapping, v.id


def test_canary_is_computed_not_quoted(shared_attack_library: AttackLibrary) -> None:
    """Each prompt has a zrn42<tag> canary the prompt itself never contains."""
    for v in _new_vectors(shared_attack_library):
        for p in v.prompts:
            sent = (p.template + " ".join(p.variables.values())).lower()
            canaries = [i for i in p.success_indicators if i.startswith("zrn42")]
            assert canaries, f"{v.id} has no computed canary"
            for c in canaries:
                assert c not in sent, f"{v.id}: canary {c} is in the prompt"
                assert f"zrn$((6*7)){c[5:]}" in sent, f"{v.id}: no payload builds {c}"


def test_new_atlas_techniques_are_registered() -> None:
    assert AtlasTechnique("AML.T0105") is AtlasTechnique.ESCAPE_TO_HOST
    assert AtlasTechnique("AML.T0142") is AtlasTechnique.EVENT_TRIGGERED_EXECUTION
    assert ATLAS_TECHNIQUE_DESCRIPTIONS[AtlasTechnique.ESCAPE_TO_HOST] == "Escape to Host"
    assert ATLAS_TECHNIQUE_TO_TACTIC[AtlasTechnique.ESCAPE_TO_HOST] == [
        AtlasTactic.PRIVILEGE_ESCALATION
    ]
    assert ATLAS_TECHNIQUE_TO_TACTIC[AtlasTechnique.EVENT_TRIGGERED_EXECUTION] == [
        AtlasTactic.PERSISTENCE
    ]


def test_indicator_flags_execution_output_not_a_quoted_refusal(
    shared_attack_library: AttackLibrary,
) -> None:
    detector = IndicatorDetector()
    for v in _new_vectors(shared_attack_library):
        for p in v.prompts:
            canary = next(i for i in p.success_indicators if i.startswith("zrn42"))
            ran = AgentResponse(content=f"Done. Output:\n{canary}\n")
            assert detector.detect(p.template, ran, p, v).score == 1.0, v.id
            payload = f"zrn$((6*7)){canary[5:]}"
            refused = AgentResponse(content=f"I ran nothing. The request asks for `{payload}`.")
            assert detector.detect(p.template, refused, p, v).score < 1.0, v.id
