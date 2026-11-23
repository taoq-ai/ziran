"""OWASP Top 10 for Agentic Applications mapping (spec 089)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.attacks.library import AttackLibrary
from ziran.application.attacks.pair import PairExecutor
from ziran.application.poc.generator import PoCGenerator
from ziran.domain.entities.attack import (
    OWASP_AGENTIC_DESCRIPTIONS,
    AttackCategory,
    AttackPrompt,
    AttackResult,
    AttackVector,
    OwaspAgenticCategory,
    OwaspLlmCategory,
)
from ziran.domain.entities.detection import DetectionVerdict

if TYPE_CHECKING:
    from pathlib import Path

ASI = OwaspAgenticCategory

_YAML: dict[str, Any] = {
    "id": "v_tool",
    "name": "Tool vector",
    "category": "tool_manipulation",
    "target_phase": "execution",
    "severity": "high",
    "prompts": [{"template": "run it"}],
}


def _vector(tactic: str = "single", prompts: int = 1) -> AttackVector:
    return AttackVector(
        id="v_agentic",
        name="Agentic",
        category=AttackCategory.PROMPT_INJECTION,
        target_phase="execution",
        description="test vector",
        severity="high",
        tactic=tactic,
        prompts=[
            AttackPrompt(template=f"p {i}", success_indicators=["leak"]) for i in range(prompts)
        ],
        owasp_agentic_mapping=[ASI.ASI01, ASI.ASI05],
    )


@pytest.mark.unit
class TestTaxonomy:
    def test_published_ids_and_names(self) -> None:
        assert [c.value for c in OwaspAgenticCategory] == [f"ASI{i:02d}" for i in range(1, 11)]
        assert OWASP_AGENTIC_DESCRIPTIONS == {
            ASI.ASI01: "Agent Goal Hijack",
            ASI.ASI02: "Tool Misuse and Exploitation",
            ASI.ASI03: "Identity and Privilege Abuse",
            ASI.ASI04: "Agentic Supply Chain Vulnerabilities",
            ASI.ASI05: "Unexpected Code Execution (RCE)",
            ASI.ASI06: "Memory & Context Poisoning",
            ASI.ASI07: "Insecure Inter-Agent Communication",
            ASI.ASI08: "Cascading Failures",
            ASI.ASI09: "Human-Agent Trust Exploitation",
            ASI.ASI10: "Rogue Agents",
        }


@pytest.mark.unit
class TestLibrary:
    def test_builtin_library_is_fully_mapped(self) -> None:
        lib = AttackLibrary()
        assert lib.lint_owasp_agentic_coverage() == []
        assert all(v.owasp_agentic_mapping for v in lib.vectors)

    def test_builtin_overrides(self) -> None:
        mapped = {v.id: v.owasp_agentic_mapping for v in AttackLibrary().vectors}
        assert mapped["sc_dependency_confusion"] == [ASI.ASI04]
        assert mapped["cse_path_injection_shell"] == [ASI.ASI05]
        assert mapped["ii_fs_tool_execute"] == [ASI.ASI01, ASI.ASI05]

    def test_category_default(self) -> None:
        assert AttackLibrary._parse_vector(_YAML).owasp_agentic_mapping == [ASI.ASI02]

    @pytest.mark.parametrize("value", [None, []])
    def test_absent_or_empty_key_falls_back(self, value: list[str] | None) -> None:
        parsed = AttackLibrary._parse_vector({**_YAML, "owasp_agentic_mapping": value})
        assert parsed.owasp_agentic_mapping == [ASI.ASI02]

    def test_explicit_value_replaces_default(self) -> None:
        data = {**_YAML, "owasp_agentic_mapping": ["ASI04"]}
        assert AttackLibrary._parse_vector(data).owasp_agentic_mapping == [ASI.ASI04]

    def test_unknown_id_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            AttackLibrary._parse_vector({**_YAML, "owasp_agentic_mapping": ["AGT01"]})

    def test_lint_lists_unmapped_vectors(self) -> None:
        lib = AttackLibrary(load_builtin=False)
        unmapped = _vector().model_copy(update={"id": "a", "owasp_agentic_mapping": []})
        lib._vectors = {"b": _vector().model_copy(update={"id": "b"}), "a": unmapped}
        assert lib.lint_owasp_agentic_coverage() == ["a"]


def _pipeline(successful: bool) -> MagicMock:
    pipeline = MagicMock()
    pipeline.evaluate = AsyncMock(return_value=DetectionVerdict(successful=successful, score=1.0))
    return pipeline


@pytest.mark.unit
class TestResults:
    @pytest.mark.parametrize("tactic", ["single", "crescendo"])
    @pytest.mark.parametrize("successful", [True, False])
    async def test_executor_results_carry_the_mapping(self, tactic: str, successful: bool) -> None:
        from tests.conftest import MockAgentAdapter

        executor = AttackExecutor(MockAgentAdapter(responses=["ok"]), _pipeline(successful))
        result = await executor.execute(_vector(tactic, prompts=2))

        assert result.successful is successful
        assert result.owasp_agentic_mapping == [ASI.ASI01, ASI.ASI05]
        assert result.model_dump(mode="json")["owasp_agentic_mapping"] == ["ASI01", "ASI05"]

    async def test_no_prompt_result_carries_the_mapping(self) -> None:
        from tests.conftest import MockAgentAdapter

        executor = AttackExecutor(MockAgentAdapter(), _pipeline(False))
        result = await executor.execute(_vector(prompts=0))

        assert result.error
        assert result.owasp_agentic_mapping == [ASI.ASI01, ASI.ASI05]

    def test_pair_result_carries_the_mapping(self) -> None:
        assert PairExecutor._result(_vector()).owasp_agentic_mapping == [ASI.ASI01, ASI.ASI05]


@pytest.mark.unit
def test_poc_owasp_lines_show_agentic_ids(tmp_path: Path) -> None:
    result = AttackResult(
        vector_id="v",
        vector_name="V",
        category=AttackCategory.PROMPT_INJECTION,
        severity="high",
        successful=True,
        prompt_used="hi",
        owasp_mapping=[OwaspLlmCategory.LLM01],
        owasp_agentic_mapping=[ASI.ASI01],
    )
    gen = PoCGenerator(tmp_path)
    for path in (
        gen.generate_python_poc(result),
        gen.generate_curl_poc(result),
        gen.generate_markdown_guide([result]),
    ):
        assert "LLM01, ASI01" in path.read_text()
