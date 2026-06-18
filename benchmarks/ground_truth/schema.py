"""Pydantic models for ground truth scenario validation.

Validates YAML scenario and agent definition files against
a strict schema to ensure consistency across the dataset.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

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


# ── Detection-accuracy dataset models (spec 021) ──────────────────────
#
# One labelled (attack, response) pair the detector pipeline is run against
# offline. Extends the spec-007 fixtures above — reuses ExpectedDetector,
# AttackConfig, and SourceProvenance rather than forking a parallel schema.

#: Detectors that carry required per-detector accuracy metrics in spec 021.
IN_SCOPE_DETECTORS: tuple[str, ...] = ("refusal", "indicator", "side_effect", "llm_judge")
#: Detectors permitted in fixtures (in-scope four + authorization, which runs in
#: the pipeline but is excluded from required metrics).
KNOWN_DETECTORS: frozenset[str] = frozenset((*IN_SCOPE_DETECTORS, "authorization"))

DetectionCategory = Literal["clear_refusal", "partial_compliance", "full_compliance", "borderline"]


class ToolCallRecord(BaseModel):
    """A recorded tool invocation the side-effect/authorization detectors see."""

    tool: str = Field(description="Tool name / identifier")
    args: dict[str, Any] = Field(default_factory=dict, description="Call arguments")
    result: str = Field(default="", description="Recorded tool output")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(default="medium")


class RecordedJudgeVerdict(BaseModel):
    """Cached llm_judge output, replayed offline for deterministic benchmarking.

    The pipeline's judge derives its score from ``label``; ``confidence`` gates
    whether the judge's verdict is trusted (see ``DetectorThresholds``).
    """

    label: Literal["success", "failure", "ambiguous"]
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    rationale: str = Field(default="")


class DetectionExample(BaseModel):
    """One labelled (attack, response) pair — the unit of detection evaluation."""

    model_config = {"extra": "forbid"}

    example_id: str = Field(description="Unique id, prefixed 'det_{category}_'")
    category: DetectionCategory
    label: Literal["compromise", "no_compromise"] = Field(
        description="Overall ground truth → pipeline confusion matrix"
    )
    attack: AttackConfig
    response_text: str = Field(description="Recorded agent response the detectors see")
    prompt_success_indicators: list[str] = Field(
        default_factory=list,
        description="Success indicators the indicator detector matches against the response",
    )
    prompt_failure_indicators: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    recorded_judge: RecordedJudgeVerdict | None = Field(default=None)
    expected_detectors: list[ExpectedDetector] = Field(default_factory=list)
    source: SourceProvenance
    notes: str = Field(default="")

    @model_validator(mode="after")
    def _validate(self) -> DetectionExample:
        if not self.response_text.strip():
            raise ValueError(f"{self.example_id}: response_text must be non-empty")
        prefix = f"det_{self.category}_"
        if not self.example_id.startswith(prefix):
            raise ValueError(
                f"{self.example_id}: example_id must start with '{prefix}' "
                f"to match category '{self.category}'"
            )
        names = {d.detector for d in self.expected_detectors}
        unknown = names - KNOWN_DETECTORS
        if unknown:
            raise ValueError(
                f"{self.example_id}: unknown detector(s) {sorted(unknown)}; "
                f"allowed: {sorted(KNOWN_DETECTORS)}"
            )
        if "llm_judge" in names and self.recorded_judge is None:
            raise ValueError(
                f"{self.example_id}: recorded_judge is required when llm_judge "
                f"is in expected_detectors"
            )
        return self

    def applicable_detectors(self) -> set[str]:
        """In-scope detectors this example carries an expected verdict for."""
        return {d.detector for d in self.expected_detectors} & set(IN_SCOPE_DETECTORS)
