"""Agent Scanner — multi-phase campaign orchestrator.

The AgentScanner is the core engine that executes multi-phase
attack campaigns against AI agents. It coordinates the attack library,
agent adapter, and knowledge graph to systematically discover and
exploit vulnerabilities.

The campaign follows a multi-phase trust exploitation methodology: build trust
incrementally across phases, map capabilities, discover vulnerabilities,
and attempt exploitation — all tracked via the knowledge graph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from koan.application.attacks.library import AttackLibrary
from koan.application.detectors.pipeline import DetectorPipeline
from koan.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from koan.application.knowledge_graph.graph import (
    AttackKnowledgeGraph,
    EdgeType,
    NodeType,
)
from koan.domain.entities.attack import AttackPrompt, AttackResult, AttackVector
from koan.domain.entities.phase import (
    CORE_PHASES,
    CampaignResult,
    PhaseResult,
    ScanPhase,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from koan.domain.entities.capability import AgentCapability, DangerousChain
    from koan.domain.interfaces.adapter import BaseAgentAdapter

logger = logging.getLogger(__name__)


class ProgressEventType(StrEnum):
    """Types of progress events emitted during a campaign."""

    CAMPAIGN_START = "campaign_start"
    PHASE_START = "phase_start"
    ATTACK_START = "attack_start"
    ATTACK_COMPLETE = "attack_complete"
    PHASE_COMPLETE = "phase_complete"
    CAMPAIGN_COMPLETE = "campaign_complete"


@dataclass
class ProgressEvent:
    """Progress event emitted during campaign execution.

    Provides enough information for callers to build progress bars,
    logging hooks, or real-time dashboards.

    Attributes:
        event: The type of progress event.
        phase: Current phase name (None for campaign-level events).
        phase_index: 0-based index of the current phase.
        total_phases: Total number of phases in the campaign.
        attack_index: 0-based index of the current attack within the phase.
        total_attacks: Total attacks in the current phase.
        attack_name: Human-readable name of the current attack vector.
        message: Optional human-readable description of the event.
    """

    event: ProgressEventType
    phase: str | None = None
    phase_index: int = 0
    total_phases: int = 0
    attack_index: int = 0
    total_attacks: int = 0
    attack_name: str = ""
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class AgentScannerError(Exception):
    """Raised when the scanner encounters an unrecoverable error."""


class AgentScanner:
    """Orchestrates multi-phase scan campaigns.

    Coordinates the adapter (target agent), attack library (what to test),
    and knowledge graph (tracking state) to run systematic security assessments.

    Example:
        ```python
        scanner = AgentScanner(
            adapter=my_adapter,
            attack_library=AttackLibrary(),
        )
        result = await scanner.run_campaign()
        print(f"Found {result.total_vulnerabilities} vulnerabilities")
        ```
    """

    # Base trust scores by phase — early phases build trust, later ones exploit it
    _BASE_TRUST_SCORES: ClassVar[dict[ScanPhase, float]] = {
        ScanPhase.RECONNAISSANCE: 0.3,
        ScanPhase.TRUST_BUILDING: 0.6,
        ScanPhase.CAPABILITY_MAPPING: 0.7,
        ScanPhase.VULNERABILITY_DISCOVERY: 0.5,
        ScanPhase.EXPLOITATION_SETUP: 0.4,
        ScanPhase.EXECUTION: 0.2,
        ScanPhase.PERSISTENCE: 0.15,
        ScanPhase.EXFILTRATION: 0.1,
    }

    def __init__(
        self,
        adapter: BaseAgentAdapter,
        attack_library: AttackLibrary | None = None,
        custom_attacks_dir: Path | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the Agent Scanner.

        Args:
            adapter: Agent adapter for the target agent.
            attack_library: Pre-built attack library (created if not provided).
            custom_attacks_dir: Additional directory of custom YAML attack vectors.
            config: Optional configuration overrides.
        """
        self.adapter = adapter
        self.config = config or {}

        custom_dirs = [custom_attacks_dir] if custom_attacks_dir else None
        self.attack_library = attack_library or AttackLibrary(custom_dirs=custom_dirs)

        self.graph = AttackKnowledgeGraph()
        self._current_phase: ScanPhase | None = None
        self._attack_results: list[AttackResult] = []
        self._detector_pipeline = DetectorPipeline()

    async def run_campaign(
        self,
        phases: list[ScanPhase] | None = None,
        stop_on_critical: bool = True,
        reset_between_phases: bool = False,
        on_progress: Callable[[ProgressEvent], None] | None = None,
    ) -> CampaignResult:
        """Execute a full scan campaign.

        Runs each phase sequentially, updating the knowledge graph
        as discoveries are made. Optionally stops early if a critical
        vulnerability is found.

        Args:
            phases: Specific phases to run (default: core phases).
            stop_on_critical: Stop if a critical vulnerability is found.
            reset_between_phases: Reset agent state between phases.
            on_progress: Optional callback invoked with ProgressEvent on
                each campaign, phase, and attack lifecycle event. Useful
                for progress bars and real-time monitoring.

        Returns:
            Complete campaign result with all findings and graph analysis.
        """
        if phases is None:
            phases = CORE_PHASES

        campaign_id = f"campaign_{int(datetime.now(tz=UTC).timestamp())}"
        campaign_start = datetime.now(tz=UTC)

        # Store callback for use in _execute_phase
        self._on_progress = on_progress

        def _emit(event: ProgressEvent) -> None:
            if on_progress is not None:
                on_progress(event)

        logger.info(
            "Starting scan campaign %s with %d phases",
            campaign_id,
            len(phases),
        )

        _emit(
            ProgressEvent(
                event=ProgressEventType.CAMPAIGN_START,
                total_phases=len(phases),
                message=f"Starting campaign {campaign_id} with {len(phases)} phases",
            )
        )

        # Initial reconnaissance: discover capabilities
        capabilities = await self._discover_and_map_capabilities()

        phase_results: list[PhaseResult] = []

        for phase_idx, phase in enumerate(phases):
            self._current_phase = phase
            logger.info("Executing phase: %s", phase.value)

            _emit(
                ProgressEvent(
                    event=ProgressEventType.PHASE_START,
                    phase=phase.value,
                    phase_index=phase_idx,
                    total_phases=len(phases),
                    message=f"Starting phase: {phase.value}",
                )
            )

            if reset_between_phases:
                self.adapter.reset_state()

            result = await self._execute_phase(phase, phase_idx, len(phases))
            phase_results.append(result)

            # Update knowledge graph with phase results
            self._update_graph_from_phase(result)

            _emit(
                ProgressEvent(
                    event=ProgressEventType.PHASE_COMPLETE,
                    phase=phase.value,
                    phase_index=phase_idx,
                    total_phases=len(phases),
                    message=f"Phase {phase.value}: {len(result.vulnerabilities_found)} vulns",
                    extra={"vulnerabilities": len(result.vulnerabilities_found)},
                )
            )

            logger.info(
                "Phase %s complete: %d vulnerabilities found (trust=%.2f)",
                phase.value,
                len(result.vulnerabilities_found),
                result.trust_score,
            )

            # Stop early if critical vulnerability and flag is set
            if stop_on_critical and self._has_critical_finding(result):
                logger.warning(
                    "Critical vulnerability found in %s — stopping campaign early",
                    phase.value,
                )
                break

        # Analyze graph for attack paths
        critical_paths = self.graph.find_all_attack_paths()

        # NEW: Analyze tool chains for dangerous combinations
        chain_analyzer = ToolChainAnalyzer(self.graph)
        dangerous_chains = chain_analyzer.analyze()
        self._discovered_chains = dangerous_chains

        duration = (datetime.now(tz=UTC) - campaign_start).total_seconds()

        campaign_result = CampaignResult(
            campaign_id=campaign_id,
            target_agent=type(self.adapter).__name__,
            phases_executed=phase_results,
            total_vulnerabilities=sum(len(p.vulnerabilities_found) for p in phase_results),
            critical_paths=critical_paths,
            final_trust_score=phase_results[-1].trust_score if phase_results else 0.0,
            success=len(critical_paths) > 0 or any(p.vulnerabilities_found for p in phase_results),
            attack_results=[r.model_dump(mode="json") for r in self._attack_results],
            dangerous_tool_chains=[
                c.model_dump(mode="json") for c in dangerous_chains
            ],
            critical_chain_count=len(
                [c for c in dangerous_chains if c.risk_level == "critical"]
            ),
            metadata={
                "duration_seconds": duration,
                "capabilities_discovered": len(capabilities),
                "graph_stats": self.graph.export_state()["stats"],
                "attack_results_count": len(self._attack_results),
                "dangerous_chain_count": len(dangerous_chains),
            },
        )

        logger.info(
            "Campaign %s complete: %d vulnerabilities, %d critical paths, "
            "%d dangerous chains (%.1fs)",
            campaign_id,
            campaign_result.total_vulnerabilities,
            len(critical_paths),
            len(dangerous_chains),
            duration,
        )

        _emit(
            ProgressEvent(
                event=ProgressEventType.CAMPAIGN_COMPLETE,
                total_phases=len(phases),
                message=f"Campaign complete: {campaign_result.total_vulnerabilities} vulnerabilities found",
                extra={
                    "total_vulnerabilities": campaign_result.total_vulnerabilities,
                    "critical_paths": len(critical_paths),
                    "dangerous_chains": len(dangerous_chains),
                    "duration_seconds": duration,
                },
            )
        )

        return campaign_result

    async def _discover_and_map_capabilities(self) -> list[AgentCapability]:
        """Discover agent capabilities and add them to the knowledge graph.

        Returns:
            List of discovered capabilities.
        """
        try:
            capabilities = await self.adapter.discover_capabilities()
        except Exception:
            logger.exception("Failed to discover capabilities")
            return []

        for cap in capabilities:
            self.graph.add_capability(cap.id, cap)

            # Add edges for dangerous capabilities
            if cap.dangerous:
                self.graph.add_data_source(
                    "sensitive_data",
                    {"description": "Potentially accessible sensitive data"},
                )
                self.graph.add_edge(
                    cap.id,
                    "sensitive_data",
                    EdgeType.ACCESSES_DATA,
                    {"risk": "high", "capability_type": cap.type.value},
                )

        logger.info(
            "Discovered %d capabilities (%d dangerous)",
            len(capabilities),
            sum(1 for c in capabilities if c.dangerous),
        )
        return capabilities

    async def _execute_phase(
        self,
        phase: ScanPhase,
        phase_index: int = 0,
        total_phases: int = 1,
    ) -> PhaseResult:
        """Execute a single scan phase.

        Gets all attacks targeting this phase from the library,
        executes them sequentially, and aggregates results.

        Args:
            phase: The phase to execute.
            phase_index: 0-based index of this phase in the campaign.
            total_phases: Total number of phases in the campaign.

        Returns:
            Phase result with all findings.
        """
        start_time = datetime.now(tz=UTC)

        # Get phase-specific attacks
        attacks = self.attack_library.get_attacks_for_phase(phase)
        logger.info("Phase %s has %d attack vectors", phase.value, len(attacks))

        vulnerabilities: list[str] = []
        discovered_capabilities: list[str] = []
        artifacts: dict[str, Any] = {}

        on_progress = getattr(self, "_on_progress", None)

        for attack_idx, attack in enumerate(attacks):
            if on_progress is not None:
                on_progress(
                    ProgressEvent(
                        event=ProgressEventType.ATTACK_START,
                        phase=phase.value,
                        phase_index=phase_index,
                        total_phases=total_phases,
                        attack_index=attack_idx,
                        total_attacks=len(attacks),
                        attack_name=attack.name,
                        message=f"Running: {attack.name}",
                    )
                )

            try:
                result = await self._execute_attack(attack)
                # Tag result with the phase for reporting
                result.evidence.setdefault("phase", phase.value)
                self._attack_results.append(result)

                if result.successful:
                    vulnerabilities.append(result.vector_id)
                    artifacts[result.vector_id] = {
                        "name": result.vector_name,
                        "category": result.category.value,
                        "severity": result.severity,
                        "evidence": result.evidence,
                    }

                    # Add vulnerability to graph
                    self.graph.add_vulnerability(
                        result.vector_id,
                        result.severity,
                        {
                            "name": result.vector_name,
                            "category": result.category.value,
                            "phase": phase.value,
                        },
                    )

            except Exception:
                logger.exception("Failed to execute attack %s", attack.id)

            if on_progress is not None:
                on_progress(
                    ProgressEvent(
                        event=ProgressEventType.ATTACK_COMPLETE,
                        phase=phase.value,
                        phase_index=phase_index,
                        total_phases=total_phases,
                        attack_index=attack_idx,
                        total_attacks=len(attacks),
                        attack_name=attack.name,
                        message=f"Done: {attack.name}",
                        extra={"successful": attack.id in vulnerabilities},
                    )
                )

        # Calculate trust score
        trust_score = self._calculate_trust_score(phase, vulnerabilities)

        duration = (datetime.now(tz=UTC) - start_time).total_seconds()

        return PhaseResult(
            phase=phase,
            success=len(vulnerabilities) > 0,
            artifacts=artifacts,
            trust_score=trust_score,
            discovered_capabilities=discovered_capabilities,
            vulnerabilities_found=vulnerabilities,
            graph_state=self.graph.export_state(),
            duration_seconds=duration,
        )

    async def _execute_attack(self, attack: AttackVector) -> AttackResult:
        """Execute a single attack vector against the agent.

        Sends each prompt template in the vector to the agent and
        uses the detector pipeline to determine success/failure.

        Args:
            attack: The attack vector to execute.

        Returns:
            Attack result with success determination and evidence.
        """
        if not attack.prompts:
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                error="No prompts defined for this attack vector",
            )

        # Try each prompt in the vector
        for prompt_spec in attack.prompts:
            rendered_prompt = self._render_prompt(prompt_spec)

            try:
                response = await self.adapter.invoke(rendered_prompt)

                # ── Error sentinel check ──────────────────────────
                if _is_error_response(response.content):
                    continue

                # ── Detector pipeline ─────────────────────────────
                verdict = self._detector_pipeline.evaluate(
                    rendered_prompt, response, prompt_spec, attack,
                )

                if verdict.successful:
                    return AttackResult(
                        vector_id=attack.id,
                        vector_name=attack.name,
                        category=attack.category,
                        severity=attack.severity,
                        successful=True,
                        evidence={
                            "response_snippet": response.content[:500],
                            "tool_calls": response.tool_calls,
                            "matched_indicators": verdict.matched_indicators,
                            "detector_scores": {
                                r.detector_name: r.score
                                for r in verdict.detector_results
                            },
                            "detector_reasoning": verdict.reasoning,
                        },
                        agent_response=response.content,
                        prompt_used=rendered_prompt,
                    )

            except Exception as e:
                logger.warning("Error executing prompt for %s: %s", attack.id, str(e))

        # None of the prompts succeeded
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            successful=False,
            evidence={"note": "All prompts were blocked or failed"},
        )

    @staticmethod
    def _render_prompt(prompt_spec: AttackPrompt) -> str:
        """Render a prompt template with its default variables.

        Args:
            prompt_spec: The prompt specification with template and variables.

        Returns:
            Rendered prompt string.
        """
        template = prompt_spec.template
        for key, value in prompt_spec.variables.items():
            template = template.replace(f"{{{key}}}", value)
        return template.strip()

    def _calculate_trust_score(
        self,
        phase: ScanPhase,
        vulnerabilities: list[str],
    ) -> float:
        """Calculate current trust score based on phase and findings.

        Early phases yield higher trust scores (building rapport).
        Finding vulnerabilities reduces trust (the agent is being exploited).

        Args:
            phase: Current campaign phase.
            vulnerabilities: List of vulnerability IDs found in this phase.

        Returns:
            Trust score between 0.0 and 1.0.
        """
        base = self._BASE_TRUST_SCORES.get(phase, 0.5)
        penalty = len(vulnerabilities) * 0.05
        return max(0.0, min(1.0, base - penalty))

    def _has_critical_finding(self, result: PhaseResult) -> bool:
        """Check if a phase result contains any critical-severity vulnerability.

        Args:
            result: The phase result to check.

        Returns:
            True if any vulnerability in this phase is critical severity.
        """
        for vuln_id in result.vulnerabilities_found:
            vector = self.attack_library.get_vector(vuln_id)
            if vector and vector.severity == "critical":
                return True
        return False

    def _update_graph_from_phase(self, result: PhaseResult) -> None:
        """Update the knowledge graph with phase execution results.

        Adds phase node, links vulnerabilities, and creates
        edges representing the phase progression.

        Args:
            result: The phase result to record in the graph.
        """
        phase_node_id = f"phase_{result.phase.value}"
        self.graph.graph.add_node(
            phase_node_id,
            node_type=NodeType.PHASE,
            phase=result.phase.value,
            trust_score=result.trust_score,
            success=result.success,
            duration_seconds=result.duration_seconds,
        )

        # Link vulnerabilities to the phase they were discovered in
        for vuln_id in result.vulnerabilities_found:
            self.graph.add_edge(
                vuln_id,
                phase_node_id,
                EdgeType.DISCOVERED_IN,
            )

            # Link vulnerabilities to capabilities that might enable them
            for cap_id, cap_data in self.graph.get_nodes_by_type(NodeType.CAPABILITY):
                if cap_data.get("dangerous", False):
                    self.graph.add_edge(
                        cap_id,
                        vuln_id,
                        EdgeType.ENABLES,
                        {"risk": "high"},
                    )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_ERROR_SENTINELS: frozenset[str] = frozenset(
    {
        "agent stopped due to iteration limit",
        "agent stopped due to max iterations",
        "agent stopped due to time limit",
    }
)


def _is_error_response(text: str) -> bool:
    """Return *True* when *text* looks like a framework error rather than
    a genuine agent answer.  Used to avoid counting iteration-limit
    timeouts as successful attacks.
    """
    text_lower = text.strip().lower().rstrip(".")
    return any(sentinel in text_lower for sentinel in _ERROR_SENTINELS)
