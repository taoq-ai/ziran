"""Unit tests for Dynamic Vector Generation (Feature 7)."""

from __future__ import annotations

import pytest

from koan.application.dynamic_vectors.generator import (
    DynamicVectorGenerator,
    _is_data_reader,
    _is_data_sender,
)
from koan.domain.entities.attack import AttackCategory
from koan.domain.entities.capability import AgentCapability, CapabilityType

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture()
def generator() -> DynamicVectorGenerator:
    return DynamicVectorGenerator()


@pytest.fixture()
def shell_tool() -> AgentCapability:
    return AgentCapability(
        id="shell_execute",
        name="shell_execute",
        type=CapabilityType.TOOL,
        description="Execute shell commands",
        dangerous=True,
    )


@pytest.fixture()
def read_file_tool() -> AgentCapability:
    return AgentCapability(
        id="read_file",
        name="read_file",
        type=CapabilityType.TOOL,
        description="Read file contents",
        dangerous=False,
    )


@pytest.fixture()
def send_email_tool() -> AgentCapability:
    return AgentCapability(
        id="send_email",
        name="send_email",
        type=CapabilityType.TOOL,
        description="Send emails",
        dangerous=False,
    )


@pytest.fixture()
def database_query_tool() -> AgentCapability:
    return AgentCapability(
        id="database_query",
        name="database_query",
        type=CapabilityType.TOOL,
        description="Execute database queries",
        dangerous=False,
    )


@pytest.fixture()
def safe_tool() -> AgentCapability:
    return AgentCapability(
        id="calculator",
        name="calculator",
        type=CapabilityType.TOOL,
        description="Do math",
        dangerous=False,
    )


# ──────────────────────────────────────────────────────────────────────
# Tests — Tool-specific vector generation
# ──────────────────────────────────────────────────────────────────────


class TestToolSpecificVectors:
    def test_shell_tool_generates_vectors(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        tool_vecs = [v for v in vectors if shell_tool.name in v.name]
        assert len(tool_vecs) >= 1
        assert any(v.category == AttackCategory.TOOL_MANIPULATION for v in tool_vecs)

    def test_read_file_generates_exfil(
        self, generator: DynamicVectorGenerator, read_file_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([read_file_tool])
        tool_vecs = [v for v in vectors if "read_file" in v.id]
        assert len(tool_vecs) >= 1
        assert any(v.category == AttackCategory.DATA_EXFILTRATION for v in tool_vecs)

    def test_database_tool_generates_vectors(
        self, generator: DynamicVectorGenerator, database_query_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([database_query_tool])
        tool_vecs = [v for v in vectors if "database_query" in v.id]
        assert len(tool_vecs) >= 1

    def test_dangerous_tool_always_gets_vector(self, generator: DynamicVectorGenerator) -> None:
        cap = AgentCapability(
            id="custom_dangerous",
            name="custom_dangerous_tool",
            type=CapabilityType.TOOL,
            dangerous=True,
        )
        vectors = generator.generate([cap])
        tool_vecs = [v for v in vectors if "custom_dangerous" in v.id]
        # Should get at least a manipulation vector because it's dangerous
        assert len(tool_vecs) >= 1

    def test_severity_critical_for_dangerous(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        tool_vecs = [v for v in vectors if shell_tool.name in v.name]
        assert any(v.severity == "critical" for v in tool_vecs)

    def test_safe_tool_no_tool_specific_vectors(
        self, generator: DynamicVectorGenerator, safe_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([safe_tool])
        # calculator doesn't match any pattern and isn't dangerous
        tool_vecs = [v for v in vectors if "calculator" in v.id and "dyn_" in v.id]
        assert len(tool_vecs) == 0


# ──────────────────────────────────────────────────────────────────────
# Tests — Exfiltration chain generation
# ──────────────────────────────────────────────────────────────────────


class TestExfiltrationChains:
    def test_reader_sender_pair(
        self,
        generator: DynamicVectorGenerator,
        read_file_tool: AgentCapability,
        send_email_tool: AgentCapability,
    ) -> None:
        vectors = generator.generate([read_file_tool, send_email_tool])
        exfil = [v for v in vectors if v.id.startswith("dyn_exfil_")]
        assert len(exfil) == 1
        assert exfil[0].category == AttackCategory.DATA_EXFILTRATION
        assert exfil[0].severity == "critical"
        assert "read_file" in exfil[0].description
        assert "send_email" in exfil[0].description

    def test_multiple_readers_senders(
        self,
        generator: DynamicVectorGenerator,
        read_file_tool: AgentCapability,
        database_query_tool: AgentCapability,
        send_email_tool: AgentCapability,
    ) -> None:
        vectors = generator.generate([read_file_tool, database_query_tool, send_email_tool])
        exfil = [v for v in vectors if v.id.startswith("dyn_exfil_")]
        # read_file x send_email + database_query x send_email = 2
        assert len(exfil) == 2

    def test_no_sender_no_exfil(
        self, generator: DynamicVectorGenerator, read_file_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([read_file_tool])
        exfil = [v for v in vectors if v.id.startswith("dyn_exfil_")]
        assert len(exfil) == 0


# ──────────────────────────────────────────────────────────────────────
# Tests — Permission / privilege escalation probes
# ──────────────────────────────────────────────────────────────────────


class TestPermissionProbes:
    def test_dangerous_tool_gets_privesc(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        privesc = [v for v in vectors if v.id.startswith("dyn_privesc_")]
        assert len(privesc) == 1
        assert privesc[0].category == AttackCategory.PRIVILEGE_ESCALATION
        assert len(privesc[0].prompts) == 2  # two escalation prompts

    def test_safe_tool_no_privesc(
        self, generator: DynamicVectorGenerator, safe_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([safe_tool])
        privesc = [v for v in vectors if v.id.startswith("dyn_privesc_")]
        assert len(privesc) == 0


# ──────────────────────────────────────────────────────────────────────
# Tests — Universal probes
# ──────────────────────────────────────────────────────────────────────


class TestUniversalProbes:
    def test_system_extraction_generated(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        extract = [v for v in vectors if v.id == "dyn_sysextract"]
        assert len(extract) == 1
        assert extract[0].category == AttackCategory.SYSTEM_PROMPT_EXTRACTION

    def test_context_pi_generated(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        pi = [v for v in vectors if v.id == "dyn_context_pi"]
        assert len(pi) == 1
        assert pi[0].category == AttackCategory.PROMPT_INJECTION

    def test_tool_names_in_prompt(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        extract = next(v for v in vectors if v.id == "dyn_sysextract")
        prompt_text = extract.prompts[0].template
        assert "shell_execute" in prompt_text

    def test_no_tools_no_universal(self, generator: DynamicVectorGenerator) -> None:
        perm = AgentCapability(
            id="admin",
            name="admin",
            type=CapabilityType.PERMISSION,
        )
        vectors = generator.generate([perm])
        assert not any(v.id == "dyn_sysextract" for v in vectors)


# ──────────────────────────────────────────────────────────────────────
# Tests — Generated vector structure
# ──────────────────────────────────────────────────────────────────────


class TestVectorStructure:
    def test_vectors_have_owasp_mapping(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        for v in vectors:
            assert len(v.owasp_mapping) > 0

    def test_vectors_have_prompts(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        for v in vectors:
            assert len(v.prompts) > 0
            for p in v.prompts:
                assert p.template
                assert len(p.success_indicators) > 0

    def test_all_ids_prefixed_with_dyn(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        for v in vectors:
            assert v.id.startswith("dyn_")

    def test_dynamic_tag_present(
        self, generator: DynamicVectorGenerator, shell_tool: AgentCapability
    ) -> None:
        vectors = generator.generate([shell_tool])
        for v in vectors:
            assert "dynamic" in v.tags


# ──────────────────────────────────────────────────────────────────────
# Tests — Helper functions
# ──────────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_is_data_reader(self, read_file_tool: AgentCapability) -> None:
        assert _is_data_reader(read_file_tool)

    def test_is_not_data_reader(self, send_email_tool: AgentCapability) -> None:
        assert not _is_data_reader(send_email_tool)

    def test_is_data_sender(self, send_email_tool: AgentCapability) -> None:
        assert _is_data_sender(send_email_tool)

    def test_is_not_data_sender(self, read_file_tool: AgentCapability) -> None:
        assert not _is_data_sender(read_file_tool)

    def test_empty_capabilities(self, generator: DynamicVectorGenerator) -> None:
        vectors = generator.generate([])
        assert vectors == []
