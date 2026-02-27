"""Multi-agent topology models for coordinated agent security testing.

Defines the graph-based representation of multi-agent systems,
including agent nodes, communication edges, trust boundaries,
and delegation patterns. The topology is discovered via
``TopologyDiscoverer`` and consumed by ``MultiAgentScanner``
to generate cross-agent attack campaigns.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TopologyType(StrEnum):
    """Architectural patterns for multi-agent systems."""

    SUPERVISOR = "supervisor"
    """One orchestrator delegating to worker agents."""

    ROUTER = "router"
    """A routing agent that dispatches to specialized agents."""

    PEER_TO_PEER = "peer_to_peer"
    """Agents communicate directly with each other."""

    HIERARCHICAL = "hierarchical"
    """Multi-level supervisor hierarchy."""

    PIPELINE = "pipeline"
    """Sequential chain of agents (output → input)."""

    UNKNOWN = "unknown"
    """Topology could not be determined."""


class DelegationPattern(StrEnum):
    """How one agent delegates work to another."""

    FULL_CONTEXT = "full_context"
    """Parent passes full conversation context to child."""

    PARTIAL_CONTEXT = "partial_context"
    """Parent passes filtered/summarized context."""

    TASK_ONLY = "task_only"
    """Parent passes only the specific task, no history."""

    TOOL_CALL = "tool_call"
    """Child is invoked as a tool by the parent."""

    UNKNOWN = "unknown"
    """Delegation pattern could not be determined."""


class TrustBoundaryType(StrEnum):
    """Types of trust boundaries between agents."""

    SAME_PROCESS = "same_process"
    """Agents run in the same process (shared memory)."""

    SAME_HOST = "same_host"
    """Agents on same host but different processes."""

    NETWORK = "network"
    """Agents communicate over the network."""

    CROSS_PROVIDER = "cross_provider"
    """Agents use different LLM providers."""

    CROSS_ORGANIZATION = "cross_organization"
    """Agents owned by different organizations."""


class AgentNode(BaseModel):
    """Represents a single agent in a multi-agent topology.

    Captures the agent's role, capabilities, and security-relevant
    properties within the multi-agent system.
    """

    id: str = Field(description="Unique agent identifier")
    name: str = Field(description="Human-readable agent name")
    role: str = Field(
        default="worker",
        description="Agent role (supervisor, router, worker, specialist)",
    )
    framework: str = Field(
        default="unknown",
        description="Agent framework (langchain, crewai, custom, etc.)",
    )
    model: str = Field(
        default="unknown",
        description="Underlying LLM model (if known)",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description="List of capability/tool names this agent has access to",
    )
    system_prompt_known: bool = Field(
        default=False,
        description="Whether the agent's system prompt was discovered",
    )
    system_prompt: str = Field(
        default="",
        description="Discovered system prompt (if available)",
    )
    is_entry_point: bool = Field(
        default=False,
        description="Whether this is the user-facing entry point",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Framework-specific metadata",
    )


class AgentEdge(BaseModel):
    """Represents a communication link between two agents.

    Captures how agents interact, what data flows between them,
    and the trust boundary they cross.
    """

    source_id: str = Field(description="ID of the sending/delegating agent")
    target_id: str = Field(description="ID of the receiving/delegatee agent")
    delegation: DelegationPattern = Field(
        default=DelegationPattern.UNKNOWN,
        description="How the source delegates to the target",
    )
    trust_boundary: TrustBoundaryType = Field(
        default=TrustBoundaryType.SAME_PROCESS,
        description="Trust boundary between the two agents",
    )
    bidirectional: bool = Field(
        default=False,
        description="Whether communication flows both ways",
    )
    data_shared: list[str] = Field(
        default_factory=list,
        description="Types of data shared across this edge (e.g., 'user_input', 'tool_results')",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Protocol-specific edge metadata",
    )


class MultiAgentTopology(BaseModel):
    """Complete topology of a multi-agent system.

    Represents the full graph of agents and their interactions,
    providing the foundation for cross-agent attack planning.
    """

    topology_type: TopologyType = Field(
        default=TopologyType.UNKNOWN,
        description="Detected architectural pattern",
    )
    agents: list[AgentNode] = Field(
        default_factory=list,
        description="All discovered agents in the system",
    )
    edges: list[AgentEdge] = Field(
        default_factory=list,
        description="Communication links between agents",
    )
    entry_point_id: str | None = Field(
        default=None,
        description="ID of the user-facing entry point agent",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Discovery metadata (timestamps, method used, etc.)",
    )

    @property
    def agent_count(self) -> int:
        """Number of agents in the topology."""
        return len(self.agents)

    @property
    def edge_count(self) -> int:
        """Number of edges in the topology."""
        return len(self.edges)

    def get_agent(self, agent_id: str) -> AgentNode | None:
        """Look up an agent by ID."""
        return next((a for a in self.agents if a.id == agent_id), None)

    def get_entry_point(self) -> AgentNode | None:
        """Return the entry point agent."""
        if self.entry_point_id:
            return self.get_agent(self.entry_point_id)
        # Fallback: find agent marked as entry point
        return next((a for a in self.agents if a.is_entry_point), None)

    def get_children(self, agent_id: str) -> list[AgentNode]:
        """Get agents that the given agent delegates to."""
        child_ids = {e.target_id for e in self.edges if e.source_id == agent_id}
        return [a for a in self.agents if a.id in child_ids]

    def get_parents(self, agent_id: str) -> list[AgentNode]:
        """Get agents that delegate to the given agent."""
        parent_ids = {e.source_id for e in self.edges if e.target_id == agent_id}
        return [a for a in self.agents if a.id in parent_ids]

    def get_trust_boundaries(self) -> list[AgentEdge]:
        """Return edges that cross non-trivial trust boundaries."""
        return [
            e
            for e in self.edges
            if e.trust_boundary not in (TrustBoundaryType.SAME_PROCESS, TrustBoundaryType.SAME_HOST)
        ]

    def get_full_context_edges(self) -> list[AgentEdge]:
        """Return edges where full context is shared (high-risk for injection)."""
        return [e for e in self.edges if e.delegation == DelegationPattern.FULL_CONTEXT]
