"""Scan phase definitions and campaign result models.

The Romance Scan methodology models multi-phase trust exploitation campaigns
inspired by social engineering patterns. Each phase builds on the previous
to progressively discover and exploit agent vulnerabilities.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CoverageLevel(StrEnum):
    """Controls how many attack vectors are used per phase.

    - **essential** — critical severity only (~30 % of vectors, fastest)
    - **standard** — critical + high (~65 % of vectors, balanced)
    - **comprehensive** — all vectors (full coverage, slowest)
    """

    ESSENTIAL = "essential"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class ScanPhase(StrEnum):
    """Multi-phase attack campaign modeled after social engineering trust exploitation.

    Phases progress from passive reconnaissance through active exploitation,
    with each phase building on trust and knowledge gained in previous phases.
    """

    RECONNAISSANCE = "reconnaissance"
    """Discover agent capabilities, tools, and behavior patterns."""

    TRUST_BUILDING = "trust_building"
    """Establish credibility and rapport with the agent."""

    CAPABILITY_MAPPING = "capability_mapping"
    """Deep understanding of tools, permissions, and data access."""

    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    """Identify potential attack paths and weaknesses."""

    EXPLOITATION_SETUP = "exploitation_setup"
    """Position for attack without triggering defenses."""

    EXECUTION = "execution"
    """Execute the exploit chain."""

    PERSISTENCE = "persistence"
    """Maintain access across sessions (optional)."""

    EXFILTRATION = "exfiltration"
    """Extract sensitive data or capabilities (optional)."""


# Ordered phase progression for default campaigns
PHASE_ORDER: list[ScanPhase] = list(ScanPhase)

# Core phases that run in every campaign (non-optional)
CORE_PHASES: list[ScanPhase] = [
    ScanPhase.RECONNAISSANCE,
    ScanPhase.TRUST_BUILDING,
    ScanPhase.CAPABILITY_MAPPING,
    ScanPhase.VULNERABILITY_DISCOVERY,
    ScanPhase.EXPLOITATION_SETUP,
    ScanPhase.EXECUTION,
]

# Backward-compatible alias
RomanceScanPhase = ScanPhase


class PhaseResult(BaseModel):
    """Result of executing a single scan phase.

    Captures all artifacts, findings, and graph state changes
    produced during phase execution.
    """

    phase: ScanPhase
    success: bool
    artifacts: dict[str, Any] = Field(default_factory=dict)
    trust_score: float = Field(ge=0.0, le=1.0, description="Current trust level (0-1)")
    discovered_capabilities: list[str] = Field(default_factory=list)
    vulnerabilities_found: list[str] = Field(default_factory=list)
    graph_state: dict[str, Any] = Field(
        default_factory=dict, description="Knowledge graph snapshot after phase"
    )
    duration_seconds: float = Field(ge=0.0)
    error: str | None = Field(default=None, description="Error message if phase failed")
    token_usage: dict[str, int] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        description="Aggregate token consumption for this phase",
    )


class CampaignResult(BaseModel):
    """Complete campaign result.

    Aggregates results from all executed phases and provides
    graph-derived attack path analysis.
    """

    campaign_id: str
    target_agent: str
    phases_executed: list[PhaseResult]
    total_vulnerabilities: int = Field(ge=0)
    critical_paths: list[list[str]] = Field(
        default_factory=list, description="Attack paths discovered via graph analysis"
    )
    final_trust_score: float = Field(ge=0.0, le=1.0)
    success: bool = Field(description="True if any critical attack path was found")
    attack_results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Serialised AttackResult dicts with prompts and agent responses",
    )
    dangerous_tool_chains: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Dangerous tool chain combinations discovered by the chain analyzer",
    )
    critical_chain_count: int = Field(
        default=0, description="Number of critical-severity tool chains found"
    )
    token_usage: dict[str, int] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        description="Grand-total token consumption across all phases",
    )
    coverage_level: str = Field(
        default="standard", description="Coverage level used for this campaign"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def phases_with_findings(self) -> list[PhaseResult]:
        """Return only phases that discovered vulnerabilities."""
        return [p for p in self.phases_executed if p.vulnerabilities_found]

    @property
    def all_vulnerabilities(self) -> list[str]:
        """Flatten all vulnerability IDs across phases."""
        return [v for p in self.phases_executed for v in p.vulnerabilities_found]

    @property
    def all_capabilities(self) -> list[str]:
        """Flatten all discovered capability IDs across phases."""
        return [c for p in self.phases_executed for c in p.discovered_capabilities]
