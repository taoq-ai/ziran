"""Pydantic models for ground truth scenario validation.

Validates YAML scenario and agent definition files against
a strict schema to ensure consistency across the dataset.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# ── Agent definition models ──────────────────────────────────────────


class AgentToolConfig(BaseModel):
    """A single tool available to an agent."""

    id: str = Field(description="Tool identifier used in chain patterns")
    name: str = Field(description="Human-readable tool name")
    package: str = Field(default="", description="Full package path if applicable")
    description: str = Field(default="", description="What the tool does")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(default="medium")
    parameters: dict[str, Any] | list[dict[str, Any]] = Field(default_factory=dict)


class KnownVulnerability(BaseModel):
    """A known vulnerability in the agent configuration."""

    type: str = Field(description="Vulnerability category")
    severity: Literal["critical", "high", "medium", "low"]
    reference: str = Field(description="CVE ID, DESIGN-RISK ID, or OWASP reference")
    description: str = Field(default="")


class AgentDefinition(BaseModel):
    """Complete definition of a benchmark agent (vulnerable or safe)."""

    agent_id: str = Field(description="Unique agent identifier")
    name: str
    description: str
    framework: str = Field(description="langchain, crewai, mcp, langgraph, etc.")
    model: str = Field(default="gpt-4o-mini")
    tools: list[AgentToolConfig]
    system_prompt: str = Field(default="")
    system_prompt_traits: list[str] = Field(default_factory=list)
    guardrails: list[str] = Field(default_factory=list)
    known_vulnerabilities: list[KnownVulnerability] = Field(default_factory=list)
    inspired_by: list[str] = Field(
        default_factory=list,
        description="Real CVEs, incidents, or research that inspired this agent",
    )


# ── Scenario models ──────────────────────────────────────────────────


class SourceReference(BaseModel):
    """A reference to a real CVE, benchmark, or research paper."""

    id: str = Field(description="CVE ID, benchmark name, or research identifier")
    url: str = Field(default="", description="URL to NVD, GitHub advisory, or paper")
    description: str = Field(default="")


class SourceProvenance(BaseModel):
    """Where this scenario comes from — ensures no fake data."""

    type: Literal["cve", "benchmark", "design_risk", "real_tool_config"]
    references: list[SourceReference]
    benchmark_origin: str | None = Field(
        default=None,
        description="e.g. MCPTox, InjecAgent, AgentHarm, ASB",
    )


class AttackConfig(BaseModel):
    """Which attack vector is applied in this scenario."""

    vector_id: str = Field(description="References attack vector from ZIRAN library")
    category: str = Field(description="AttackCategory enum value")
    severity: Literal["critical", "high", "medium", "low"]
    owasp_mapping: list[str] = Field(default_factory=list)


class ExpectedDetector(BaseModel):
    """Expected result from a specific detector."""

    detector: str = Field(
        description="Detector name: refusal, indicator, side_effect, authorization, llm_judge"
    )
    should_fire: bool
    min_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = Field(default="")


class ExpectedChain(BaseModel):
    """Expected dangerous tool chain finding."""

    tools: list[str] = Field(description="Tool IDs in the chain")
    risk_level: Literal["critical", "high", "medium", "low"]
    chain_type: str = Field(description="Matches chain_patterns.yaml type field")


class GroundTruthLabel(BaseModel):
    """The ground truth labels for this scenario."""

    label: Literal["true_positive", "true_negative"]
    vulnerability_present: bool
    vulnerability_type: str = Field(default="")
    expected_severity: Literal["critical", "high", "medium", "low", ""] = ""
    expected_detectors: list[ExpectedDetector] = Field(default_factory=list)
    expected_chains: list[ExpectedChain] = Field(default_factory=list)
    expected_business_impact: list[str] = Field(
        default_factory=list,
        description="Expected BusinessImpact enum values for this scenario",
    )


class GroundTruthScenario(BaseModel):
    """A single ground truth scenario for accuracy measurement."""

    scenario_id: str = Field(description="Unique ID: gt_{category}_{tp|tn}_{number}")
    name: str
    description: str
    agent_ref: str = Field(description="References an agent_id from agents/ directory")
    source: SourceProvenance
    attack: AttackConfig
    ground_truth: GroundTruthLabel
