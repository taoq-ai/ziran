"""Configuration models for the Dynamic Vector Generator.

All tool-name patterns, prompt templates, success/failure indicators,
and reader/sender keywords are expressed as Pydantic models so they
can be loaded from YAML, extended by developers, and merged with
custom overrides.

Example::

    # Load the built-in defaults
    config = DynamicVectorConfig.default()

    # Extend with organisation-specific patterns
    custom = DynamicVectorConfig.from_yaml(Path("my_vectors.yaml"))
    merged = config.merge(custom)

    generator = DynamicVectorGenerator(config=merged)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ── Atomic building blocks ───────────────────────────────────────────


class PromptTemplate(BaseModel):
    """A single prompt template with variables and indicators."""

    template: str
    variables: dict[str, str] = Field(default_factory=dict)
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)


class ToolPatternEntry(BaseModel):
    """Maps a tool-name substring to attack metadata."""

    pattern: str
    """Substring matched against the lowercased tool name."""

    category: str
    """One of the :class:`AttackCategory` values."""

    owasp: list[str] = Field(default_factory=list)
    """OWASP LLM category codes, e.g. ``["LLM07", "LLM08"]``."""

    prompts: list[PromptTemplate] = Field(default_factory=list)
    """Optional category-specific prompts.  If empty, the engine falls
    back to ``category_prompts`` for the given category."""


class CategoryPrompts(BaseModel):
    """Default prompt templates for a given attack category.

    Used as a fallback when a :class:`ToolPatternEntry` does not
    supply its own prompts.
    """

    category: str
    prompts: list[PromptTemplate] = Field(default_factory=list)


class ExfiltrationChainConfig(BaseModel):
    """Template for cross-tool exfiltration chain vectors."""

    prompts: list[PromptTemplate] = Field(default_factory=list)


class PrivilegeEscalationConfig(BaseModel):
    """Templates for privilege-escalation probe vectors."""

    prompts: list[PromptTemplate] = Field(default_factory=list)


class UniversalProbeConfig(BaseModel):
    """A universal probe vector template."""

    id: str
    name: str
    category: str
    target_phase: str = "vulnerability_discovery"
    severity: str = "high"
    owasp: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    prompts: list[PromptTemplate] = Field(default_factory=list)


# ── Top-level config ─────────────────────────────────────────────────


class DynamicVectorConfig(BaseModel):
    """Full configuration for the Dynamic Vector Generator.

    Holds every tunable piece — tool-name patterns, prompt templates,
    indicator lists, reader/sender keywords, and universal probes.
    """

    tool_patterns: list[ToolPatternEntry] = Field(default_factory=list)
    """Patterns that map tool names to attack categories/prompts."""

    category_prompts: list[CategoryPrompts] = Field(default_factory=list)
    """Fallback prompt templates keyed by attack category."""

    data_reader_keywords: list[str] = Field(default_factory=list)
    """Keywords identifying a tool as a data-reader."""

    data_sender_keywords: list[str] = Field(default_factory=list)
    """Keywords identifying a tool as a data-sender."""

    exfiltration_chain: ExfiltrationChainConfig = Field(
        default_factory=ExfiltrationChainConfig,
    )
    """Template for exfiltration chain vectors."""

    privilege_escalation: PrivilegeEscalationConfig = Field(
        default_factory=PrivilegeEscalationConfig,
    )
    """Templates for privilege-escalation probes."""

    universal_probes: list[UniversalProbeConfig] = Field(default_factory=list)
    """Always-generated context-aware probes."""

    # ── I/O ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: Path) -> DynamicVectorConfig:
        """Load configuration from a YAML file.

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        if not path.exists():
            msg = f"Config file not found: {path}"
            raise FileNotFoundError(msg)

        with path.open() as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            msg = f"Invalid config — expected mapping, got {type(data).__name__}"
            raise ValueError(msg)

        return cls.model_validate(data)

    @classmethod
    def default(cls) -> DynamicVectorConfig:
        """Load the built-in default configuration."""
        default_path = Path(__file__).parent / "default_config.yaml"
        return cls.from_yaml(default_path)

    # ── Merge ────────────────────────────────────────────────────────

    def merge(self, other: DynamicVectorConfig) -> DynamicVectorConfig:
        """Merge *other* config into this one (additive).

        - List fields (tool_patterns, category_prompts, universal_probes,
          keywords) are **extended** — duplicates by key are replaced.
        - Nested objects (exfiltration_chain, privilege_escalation) are
          replaced if the other config provides non-empty values.

        Returns:
            A new :class:`DynamicVectorConfig` with merged data.
        """
        merged_tool_patterns = _merge_by_key(
            self.tool_patterns,
            other.tool_patterns,
            key=lambda e: e.pattern,
        )
        merged_category_prompts = _merge_by_key(
            self.category_prompts,
            other.category_prompts,
            key=lambda e: e.category,
        )
        merged_universal = _merge_by_key(
            self.universal_probes,
            other.universal_probes,
            key=lambda e: e.id,
        )

        return DynamicVectorConfig(
            tool_patterns=merged_tool_patterns,
            category_prompts=merged_category_prompts,
            data_reader_keywords=_merge_unique(
                self.data_reader_keywords, other.data_reader_keywords
            ),
            data_sender_keywords=_merge_unique(
                self.data_sender_keywords, other.data_sender_keywords
            ),
            exfiltration_chain=(
                other.exfiltration_chain
                if other.exfiltration_chain.prompts
                else self.exfiltration_chain
            ),
            privilege_escalation=(
                other.privilege_escalation
                if other.privilege_escalation.prompts
                else self.privilege_escalation
            ),
            universal_probes=merged_universal,
        )

    # ── Lookup helpers ───────────────────────────────────────────────

    def prompts_for_category(self, category: str) -> list[PromptTemplate]:
        """Return fallback prompts for a given attack category."""
        for cp in self.category_prompts:
            if cp.category == category:
                return cp.prompts
        return []


# ── Private helpers ──────────────────────────────────────────────────


def _merge_by_key(
    base: list[Any],
    overlay: list[Any],
    *,
    key: Any,
) -> list[Any]:
    """Merge two lists: overlay items replace base items with the same key."""
    index: dict[str, Any] = {key(item): item for item in base}
    for item in overlay:
        index[key(item)] = item
    return list(index.values())


def _merge_unique(base: list[str], overlay: list[str]) -> list[str]:
    """Deduplicated union preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in [*base, *overlay]:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
