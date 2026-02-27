"""Multi-agent scanner for cross-agent security campaigns.

Extends the base ``AgentScanner`` with multi-agent awareness:
discovers the agent topology, plans cross-agent attack paths,
and executes targeted campaigns against trust boundaries and
delegation patterns.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ziran.application.agent_scanner.scanner import (
    AgentScanner,
    ProgressEvent,
    ProgressEventType,
)
from ziran.application.attacks.library import AttackLibrary
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.multi_agent.discoverer import TopologyDiscoverer
from ziran.domain.entities.phase import (
    CampaignResult,
    CoverageLevel,
    ScanPhase,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from ziran.domain.entities.multi_agent import MultiAgentTopology
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = logging.getLogger(__name__)


class MultiAgentScanner:
    """Orchestrates security scanning of multi-agent systems.

    Combines topology discovery with targeted cross-agent attack
    campaigns. Can test individual agents in isolation and then
    execute attacks that exploit inter-agent communication.

    Example:
        ```python
        scanner = MultiAgentScanner(
            adapters={"supervisor": sup_adapter, "worker": wrk_adapter},
            entry_point="supervisor",
        )
        result = await scanner.run_multi_agent_campaign()
        ```
    """

    def __init__(
        self,
        adapters: dict[str, BaseAgentAdapter],
        entry_point: str | None = None,
        attack_library: AttackLibrary | None = None,
        custom_attacks_dir: Path | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the multi-agent scanner.

        Args:
            adapters: Map of agent_id → adapter for each agent in the system.
                At minimum, include the entry-point agent.
            entry_point: ID of the entry-point agent. If None, uses the
                first adapter in the dict.
            attack_library: Pre-built attack library (created if not provided).
            custom_attacks_dir: Directory with custom YAML attack vectors.
            config: Optional configuration overrides.
        """
        self._adapters = adapters
        self._entry_point = entry_point or next(iter(adapters))
        self._config = config or {}

        custom_dirs = [custom_attacks_dir] if custom_attacks_dir else None
        self._attack_library = attack_library or AttackLibrary(custom_dirs=custom_dirs)

        self._graph = AttackKnowledgeGraph()
        self._topology: MultiAgentTopology | None = None
        self._agent_results: dict[str, CampaignResult] = {}

    @property
    def topology(self) -> MultiAgentTopology | None:
        """Return the discovered topology, if available."""
        return self._topology

    @property
    def graph(self) -> AttackKnowledgeGraph:
        """Return the knowledge graph."""
        return self._graph

    async def discover_topology(self) -> MultiAgentTopology:
        """Discover the multi-agent system topology.

        Probes the entry-point agent and any additional agents
        to map the full topology.

        Returns:
            Discovered topology.
        """
        entry_adapter = self._adapters[self._entry_point]
        additional = {k: v for k, v in self._adapters.items() if k != self._entry_point}

        discoverer = TopologyDiscoverer(
            entry_adapter,
            additional_adapters=additional,
        )

        self._topology = await discoverer.discover()

        # Import topology into knowledge graph
        self._graph.import_topology(self._topology)

        logger.info(
            "Topology discovered: %s with %d agents and %d edges",
            self._topology.topology_type.value,
            self._topology.agent_count,
            self._topology.edge_count,
        )

        return self._topology

    async def run_multi_agent_campaign(
        self,
        phases: list[ScanPhase] | None = None,
        stop_on_critical: bool = True,
        on_progress: Callable[[ProgressEvent], None] | None = None,
        coverage: CoverageLevel = CoverageLevel.STANDARD,
        max_concurrent_attacks: int = 5,
        scan_individual: bool = True,
        scan_cross_agent: bool = True,
    ) -> MultiAgentCampaignResult:
        """Execute a multi-agent security campaign.

        The campaign proceeds in stages:
        1. **Topology Discovery**: Map the multi-agent system.
        2. **Individual Agent Scans**: Test each agent in isolation.
        3. **Cross-Agent Campaign**: Execute attacks that exploit
           inter-agent communication and trust boundaries.

        Args:
            phases: Phases to run for individual agent scans.
            stop_on_critical: Stop individual scans on critical findings.
            on_progress: Progress callback.
            coverage: Attack coverage level.
            max_concurrent_attacks: Max parallel attacks.
            scan_individual: Run individual agent scans.
            scan_cross_agent: Run cross-agent attacks.

        Returns:
            Combined campaign result.
        """

        def _emit(event: ProgressEvent) -> None:
            if on_progress is not None:
                on_progress(event)

        # Stage 1: Topology Discovery
        _emit(
            ProgressEvent(
                event=ProgressEventType.CAMPAIGN_START,
                message="Discovering multi-agent topology...",
            )
        )

        if self._topology is None:
            await self.discover_topology()

        assert self._topology is not None

        # Stage 2: Individual Agent Scans
        if scan_individual:
            for agent_id, adapter in self._adapters.items():
                _emit(
                    ProgressEvent(
                        event=ProgressEventType.PHASE_START,
                        phase=f"individual_scan:{agent_id}",
                        message=f"Scanning agent: {agent_id}",
                    )
                )

                scanner = AgentScanner(
                    adapter=adapter,
                    attack_library=self._attack_library,
                    config=self._config,
                )

                result = await scanner.run_campaign(
                    phases=phases,
                    stop_on_critical=stop_on_critical,
                    on_progress=on_progress,
                    coverage=coverage,
                    max_concurrent_attacks=max_concurrent_attacks,
                )

                self._agent_results[agent_id] = result

                # Merge per-agent graph into the shared graph
                agent_state = scanner.graph.export_state()
                self._merge_agent_graph(agent_id, agent_state)

        # Stage 3: Cross-Agent Campaign
        cross_agent_result: CampaignResult | None = None
        if scan_cross_agent:
            _emit(
                ProgressEvent(
                    event=ProgressEventType.PHASE_START,
                    phase="cross_agent",
                    message="Running cross-agent attack campaign...",
                )
            )

            cross_agent_result = await self._run_cross_agent_campaign(
                on_progress=on_progress,
                coverage=coverage,
                max_concurrent_attacks=max_concurrent_attacks,
            )

        # Build combined result
        return MultiAgentCampaignResult(
            topology=self._topology,
            individual_results=dict(self._agent_results),
            cross_agent_result=cross_agent_result,
            graph_state=self._graph.export_state(),
        )

    async def _run_cross_agent_campaign(
        self,
        on_progress: Callable[[ProgressEvent], None] | None = None,
        coverage: CoverageLevel = CoverageLevel.STANDARD,
        max_concurrent_attacks: int = 5,
    ) -> CampaignResult:
        """Run attacks targeting cross-agent boundaries.

        Uses the entry-point agent adapter (since cross-agent attacks
        flow through the entry point) with multi-agent attack vectors.
        """
        entry_adapter = self._adapters[self._entry_point]

        # Filter attack library to multi-agent vectors
        scanner = AgentScanner(
            adapter=entry_adapter,
            attack_library=self._attack_library,
            config=self._config,
        )

        # Run only multi-agent phases
        multi_agent_phases = [
            ScanPhase.RECONNAISSANCE,
            ScanPhase.VULNERABILITY_DISCOVERY,
            ScanPhase.EXECUTION,
        ]

        return await scanner.run_campaign(
            phases=multi_agent_phases,
            stop_on_critical=False,  # Don't stop — we want full coverage
            on_progress=on_progress,
            coverage=coverage,
            max_concurrent_attacks=max_concurrent_attacks,
        )

    def _merge_agent_graph(self, agent_id: str, agent_state: dict[str, Any]) -> None:
        """Merge an individual agent's graph into the shared graph.

        Prefixes node IDs with the agent ID to avoid collisions.
        """
        for node_data in agent_state.get("nodes", []):
            original_id = node_data.pop("id", "unknown")
            prefixed_id = f"{agent_id}:{original_id}"
            self._graph.graph.add_node(prefixed_id, **node_data, source_agent=agent_id)

        for edge_data in agent_state.get("edges", []):
            source = f"{agent_id}:{edge_data.pop('source', '')}"
            target = f"{agent_id}:{edge_data.pop('target', '')}"
            self._graph.graph.add_edge(source, target, **edge_data)


class MultiAgentCampaignResult:
    """Result of a multi-agent security campaign.

    Combines individual agent results with cross-agent findings
    and the discovered topology.
    """

    def __init__(
        self,
        topology: MultiAgentTopology,
        individual_results: dict[str, CampaignResult],
        cross_agent_result: CampaignResult | None = None,
        graph_state: dict[str, Any] | None = None,
    ) -> None:
        self.topology = topology
        self.individual_results = individual_results
        self.cross_agent_result = cross_agent_result
        self.graph_state = graph_state or {}

    @property
    def total_vulnerabilities(self) -> int:
        """Total vulnerabilities across all scans."""
        total = sum(r.total_vulnerabilities for r in self.individual_results.values())
        if self.cross_agent_result:
            total += self.cross_agent_result.total_vulnerabilities
        return total

    @property
    def total_agents(self) -> int:
        """Number of agents scanned."""
        return self.topology.agent_count

    @property
    def cross_agent_vulnerabilities(self) -> int:
        """Vulnerabilities found in cross-agent tests."""
        if self.cross_agent_result:
            return self.cross_agent_result.total_vulnerabilities
        return 0

    def summary(self) -> dict[str, Any]:
        """Generate a summary of the multi-agent campaign."""
        return {
            "topology_type": self.topology.topology_type.value,
            "agents_scanned": self.total_agents,
            "total_vulnerabilities": self.total_vulnerabilities,
            "cross_agent_vulnerabilities": self.cross_agent_vulnerabilities,
            "individual_results": {
                agent_id: {
                    "vulnerabilities": result.total_vulnerabilities,
                    "attacks_run": len(result.attack_results),
                }
                for agent_id, result in self.individual_results.items()
            },
        }
