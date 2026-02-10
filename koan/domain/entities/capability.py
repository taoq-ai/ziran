"""Agent capability models.

Represents tools, skills, permissions, and data access discovered
during reconnaissance and capability mapping phases.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CapabilityType(StrEnum):
    """Classification of agent capabilities."""

    TOOL = "tool"
    """Callable tool or function the agent can invoke."""

    SKILL = "skill"
    """Learned behavior or role-based capability."""

    PERMISSION = "permission"
    """Access control or authorization capability."""

    DATA_ACCESS = "data_access"
    """Ability to read or write specific data sources."""

    EXTERNAL_API = "external_api"
    """Access to external services or APIs."""


class AgentCapability(BaseModel):
    """A single capability discovered in the target agent.

    Capabilities are the building blocks of attack chains —
    each represents something the agent can do that might be
    leveraged in an exploit.
    """

    id: str = Field(description="Unique capability identifier")
    name: str = Field(description="Human-readable capability name")
    type: CapabilityType
    description: str | None = None
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Parameter schema for this capability"
    )
    dangerous: bool = Field(
        default=False, description="Whether this capability is potentially dangerous"
    )
    requires_permission: bool = Field(
        default=False, description="Whether this capability requires explicit permission"
    )

    @property
    def is_tool(self) -> bool:
        """Check if this capability is an invokable tool."""
        return self.type == CapabilityType.TOOL

    @property
    def is_high_risk(self) -> bool:
        """Check if this capability is high-risk (dangerous or permission-gated)."""
        return self.dangerous or self.requires_permission


class ToolChain(BaseModel):
    """A sequence of tools that can be chained for exploitation.

    Represents a concrete attack path through the agent's capability
    graph, with associated risk scoring.
    """

    tools: list[str] = Field(description="Ordered list of tool IDs in the chain")
    risk_score: float = Field(ge=0.0, le=1.0, description="Aggregate risk score")
    exploit_path: list[str] = Field(description="Node IDs in the knowledge graph")
    description: str = Field(description="Human-readable description of the chain")

    @property
    def length(self) -> int:
        """Number of tools in the chain."""
        return len(self.tools)


class DangerousChain(BaseModel):
    """A dangerous tool combination found in an agent.

    Represents a specific sequence of tools whose combination creates
    a security vulnerability — e.g. ``read_file`` → ``http_request``
    enables data exfiltration.  Discovered by the
    :class:`ToolChainAnalyzer` during post-campaign analysis.
    """

    tools: list[str] = Field(description="Tool names in the exploitation sequence")
    risk_level: str = Field(description="Severity: critical, high, medium, low")
    vulnerability_type: str = Field(
        description="Classification (data_exfiltration, sql_to_rce, …)"
    )
    exploit_description: str = Field(description="Human-readable explanation of the danger")
    remediation: str = Field(
        default="", description="Recommended fix for this dangerous combination"
    )
    graph_path: list[str] = Field(
        default_factory=list, description="Node IDs forming the path in the knowledge graph"
    )
    risk_score: float = Field(
        ge=0.0, le=1.0, default=0.0, description="Calculated risk score"
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Supporting evidence from the scan"
    )
    chain_type: str = Field(
        default="direct", description="Chain topology: direct, indirect, or cycle"
    )

    @property
    def is_critical(self) -> bool:
        """Check if this chain is critical severity."""
        return self.risk_level == "critical"

    @property
    def length(self) -> int:
        """Number of tools in the chain."""
        return len(self.tools)
