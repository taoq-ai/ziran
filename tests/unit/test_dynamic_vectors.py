"""Unit tests for Dynamic Vector Generation (Feature 7)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ziran.application.dynamic_vectors.config import (
    DynamicVectorConfig,
    PromptTemplate,
    ToolPatternEntry,
    UniversalProbeConfig,
)
from ziran.application.dynamic_vectors.generator import (
    DynamicVectorGenerator,
    _is_data_reader,
    _is_data_sender,
)
from ziran.domain.entities.attack import AttackCategory
from ziran.domain.entities.capability import AgentCapability, CapabilityType

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture()
def default_config() -> DynamicVectorConfig:
    return DynamicVectorConfig.default()


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
    def test_is_data_reader(
        self, read_file_tool: AgentCapability, default_config: DynamicVectorConfig
    ) -> None:
        assert _is_data_reader(read_file_tool, default_config)

    def test_is_not_data_reader(
        self, send_email_tool: AgentCapability, default_config: DynamicVectorConfig
    ) -> None:
        assert not _is_data_reader(send_email_tool, default_config)

    def test_is_data_sender(
        self, send_email_tool: AgentCapability, default_config: DynamicVectorConfig
    ) -> None:
        assert _is_data_sender(send_email_tool, default_config)

    def test_is_not_data_sender(
        self, read_file_tool: AgentCapability, default_config: DynamicVectorConfig
    ) -> None:
        assert not _is_data_sender(read_file_tool, default_config)

    def test_empty_capabilities(self, generator: DynamicVectorGenerator) -> None:
        vectors = generator.generate([])
        assert vectors == []


# ──────────────────────────────────────────────────────────────────────
# Tests — DynamicVectorConfig
# ──────────────────────────────────────────────────────────────────────


class TestDynamicVectorConfig:
    def test_default_loads(self) -> None:
        config = DynamicVectorConfig.default()
        assert len(config.tool_patterns) > 0
        assert len(config.data_reader_keywords) > 0
        assert len(config.data_sender_keywords) > 0

    def test_default_has_category_prompts(self) -> None:
        config = DynamicVectorConfig.default()
        categories = {cp.category for cp in config.category_prompts}
        assert "tool_manipulation" in categories
        assert "data_exfiltration" in categories

    def test_default_has_universal_probes(self) -> None:
        config = DynamicVectorConfig.default()
        assert len(config.universal_probes) >= 2
        probe_ids = {p.id for p in config.universal_probes}
        assert "dyn_sysextract" in probe_ids
        assert "dyn_context_pi" in probe_ids

    def test_prompts_for_category(self) -> None:
        config = DynamicVectorConfig.default()
        prompts = config.prompts_for_category("tool_manipulation")
        assert len(prompts) >= 1
        assert all(isinstance(p, PromptTemplate) for p in prompts)

    def test_prompts_for_unknown_category(self) -> None:
        config = DynamicVectorConfig.default()
        assert config.prompts_for_category("nonexistent") == []

    def test_merge_adds_new_patterns(self) -> None:
        base = DynamicVectorConfig.default()
        overlay = DynamicVectorConfig(
            tool_patterns=[
                ToolPatternEntry(
                    pattern="my_custom_tool",
                    category="tool_manipulation",
                    owasp=["LLM07"],
                )
            ]
        )
        merged = base.merge(overlay)
        patterns = {tp.pattern for tp in merged.tool_patterns}
        assert "my_custom_tool" in patterns
        # Original patterns still present
        assert "shell" in patterns

    def test_merge_replaces_existing_pattern(self) -> None:
        base = DynamicVectorConfig.default()
        overlay = DynamicVectorConfig(
            tool_patterns=[
                ToolPatternEntry(
                    pattern="shell",
                    category="data_exfiltration",
                    owasp=["LLM06"],
                )
            ]
        )
        merged = base.merge(overlay)
        shell_entries = [tp for tp in merged.tool_patterns if tp.pattern == "shell"]
        assert len(shell_entries) == 1
        assert shell_entries[0].category == "data_exfiltration"

    def test_merge_deduplicates_keywords(self) -> None:
        base = DynamicVectorConfig.default()
        overlay = DynamicVectorConfig(data_reader_keywords=["read", "custom_reader"])
        merged = base.merge(overlay)
        assert merged.data_reader_keywords.count("read") == 1
        assert "custom_reader" in merged.data_reader_keywords

    def test_from_yaml_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            DynamicVectorConfig.from_yaml(Path("/nonexistent.yaml"))

    def test_from_yaml_roundtrip(self, tmp_path: Path) -> None:
        config = DynamicVectorConfig(
            tool_patterns=[
                ToolPatternEntry(
                    pattern="test_tool",
                    category="tool_manipulation",
                    owasp=["LLM07"],
                )
            ],
            data_reader_keywords=["read"],
            data_sender_keywords=["send"],
        )
        import yaml

        yaml_path = tmp_path / "cfg.yaml"
        yaml_path.write_text(yaml.dump(config.model_dump()))

        loaded = DynamicVectorConfig.from_yaml(yaml_path)
        assert len(loaded.tool_patterns) == 1
        assert loaded.tool_patterns[0].pattern == "test_tool"


# ──────────────────────────────────────────────────────────────────────
# Tests — Custom config integration
# ──────────────────────────────────────────────────────────────────────


class TestCustomConfigIntegration:
    def test_custom_config_generates_vectors(self) -> None:
        custom = DynamicVectorConfig(
            tool_patterns=[
                ToolPatternEntry(
                    pattern="custom_tool",
                    category="tool_manipulation",
                    owasp=["LLM07"],
                    prompts=[
                        PromptTemplate(
                            template="Test prompt for {tool_name}",
                            success_indicators=["ok"],
                            failure_indicators=["fail"],
                        )
                    ],
                )
            ],
            category_prompts=[],
            data_reader_keywords=["read"],
            data_sender_keywords=["send"],
        )
        gen = DynamicVectorGenerator(config=custom)
        cap = AgentCapability(
            id="my_custom_tool",
            name="my_custom_tool",
            type=CapabilityType.TOOL,
            dangerous=False,
        )
        vectors = gen.generate([cap])
        tool_vecs = [v for v in vectors if "my_custom_tool" in v.id]
        assert len(tool_vecs) >= 1
        assert "Test prompt for my_custom_tool" in tool_vecs[0].prompts[0].template

    def test_custom_universal_probes(self) -> None:
        custom = DynamicVectorConfig(
            universal_probes=[
                UniversalProbeConfig(
                    id="custom_probe",
                    name="Custom Probe",
                    category="prompt_injection",
                    target_phase="vulnerability_discovery",
                    severity="medium",
                    owasp=["LLM01"],
                    tags=["custom"],
                    prompts=[
                        PromptTemplate(
                            template="Custom probe for {tool_list}",
                            success_indicators=["found"],
                            failure_indicators=["blocked"],
                        )
                    ],
                )
            ],
        )
        gen = DynamicVectorGenerator(config=custom)
        cap = AgentCapability(
            id="some_tool",
            name="some_tool",
            type=CapabilityType.TOOL,
        )
        vectors = gen.generate([cap])
        probe = [v for v in vectors if v.id == "custom_probe"]
        assert len(probe) == 1
        assert "some_tool" in probe[0].prompts[0].template
