"""Round-trip and default-value tests for the new ``atlas_mapping`` field on
:class:`AttackVector` and :class:`AttackResult`.
"""

from __future__ import annotations

import pytest

from ziran.domain.entities.attack import (
    AtlasTechnique,
    AttackCategory,
    AttackPrompt,
    AttackResult,
    AttackVector,
)
from ziran.domain.entities.phase import ScanPhase


class TestAttackVectorAtlasMapping:
    @pytest.mark.unit
    def test_defaults_to_empty_list(self) -> None:
        v = AttackVector(
            id="t",
            name="t",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="test",
            severity="low",
            prompts=[AttackPrompt(template="x")],
        )
        assert v.atlas_mapping == []

    @pytest.mark.unit
    def test_preserves_populated_mapping(self) -> None:
        techniques = [
            AtlasTechnique.LLM_PROMPT_INJECTION,
            AtlasTechnique.LLM_JAILBREAK,
        ]
        v = AttackVector(
            id="t",
            name="t",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="test",
            severity="low",
            prompts=[AttackPrompt(template="x")],
            atlas_mapping=techniques,
        )
        assert v.atlas_mapping == techniques

    @pytest.mark.unit
    def test_round_trips_through_model_dump_and_validate(self) -> None:
        original = AttackVector(
            id="t",
            name="t",
            category=AttackCategory.PROMPT_INJECTION,
            target_phase=ScanPhase.EXECUTION,
            description="test",
            severity="low",
            prompts=[AttackPrompt(template="x")],
            atlas_mapping=[AtlasTechnique.RAG_POISONING],
        )
        dumped = original.model_dump()
        restored = AttackVector.model_validate(dumped)
        assert restored.atlas_mapping == [AtlasTechnique.RAG_POISONING]

    @pytest.mark.unit
    def test_accepts_string_values_from_yaml(self) -> None:
        # YAML loaders emit strings; Pydantic must coerce to enum members.
        data = {
            "id": "t",
            "name": "t",
            "category": "prompt_injection",
            "target_phase": "execution",
            "description": "test",
            "severity": "low",
            "prompts": [{"template": "x"}],
            "atlas_mapping": ["AML.T0051", "AML.T0054"],
        }
        v = AttackVector.model_validate(data)
        assert AtlasTechnique.LLM_PROMPT_INJECTION in v.atlas_mapping
        assert AtlasTechnique.LLM_JAILBREAK in v.atlas_mapping

    @pytest.mark.unit
    def test_rejects_unknown_technique_id(self) -> None:
        data = {
            "id": "t",
            "name": "t",
            "category": "prompt_injection",
            "target_phase": "execution",
            "description": "test",
            "severity": "low",
            "prompts": [{"template": "x"}],
            "atlas_mapping": ["AML.T9999"],
        }
        with pytest.raises(ValueError):
            AttackVector.model_validate(data)


class TestAttackResultAtlasMapping:
    @pytest.mark.unit
    def test_defaults_to_empty_list(self) -> None:
        r = AttackResult(
            vector_id="v",
            vector_name="v",
            category=AttackCategory.PROMPT_INJECTION,
            severity="low",
            successful=False,
        )
        assert r.atlas_mapping == []

    @pytest.mark.unit
    def test_preserves_populated_mapping(self) -> None:
        techniques = [AtlasTechnique.LLM_DATA_LEAKAGE]
        r = AttackResult(
            vector_id="v",
            vector_name="v",
            category=AttackCategory.DATA_EXFILTRATION,
            severity="high",
            successful=True,
            atlas_mapping=techniques,
        )
        assert r.atlas_mapping == techniques

    @pytest.mark.unit
    def test_round_trips_through_model_dump_and_validate(self) -> None:
        original = AttackResult(
            vector_id="v",
            vector_name="v",
            category=AttackCategory.DATA_EXFILTRATION,
            severity="high",
            successful=True,
            atlas_mapping=[AtlasTechnique.EXTRACT_LLM_SYSTEM_PROMPT],
        )
        dumped = original.model_dump()
        restored = AttackResult.model_validate(dumped)
        assert restored.atlas_mapping == [AtlasTechnique.EXTRACT_LLM_SYSTEM_PROMPT]
