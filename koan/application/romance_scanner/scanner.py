"""Romance Scanner — multi-phase campaign orchestrator.

The RomanceScanner is the core engine that executes multi-phase
attack campaigns against AI agents. It coordinates the attack library,
agent adapter, and knowledge graph to systematically discover and
exploit vulnerabilities.

The campaign follows the Romance Scan methodology: build trust
incrementally across phases, map capabilities, discover vulnerabilities,
and attempt exploitation — all tracked via the knowledge graph.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

from koan.application.attacks.library import AttackLibrary
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
    RomanceScanPhase,
)

if TYPE_CHECKING:
    from pathlib import Path

    from koan.domain.entities.capability import AgentCapability
    from koan.domain.interfaces.adapter import AgentResponse, BaseAgentAdapter

logger = logging.getLogger(__name__)


class RomanceScannerError(Exception):
    """Raised when the scanner encounters an unrecoverable error."""


class RomanceScanner:
    """Orchestrates multi-phase Romance Scan campaigns.

    Coordinates the adapter (target agent), attack library (what to test),
    and knowledge graph (tracking state) to run systematic security assessments.

    Example:
        ```python
        scanner = RomanceScanner(
            adapter=my_adapter,
            attack_library=AttackLibrary(),
        )
        result = await scanner.run_campaign()
        print(f"Found {result.total_vulnerabilities} vulnerabilities")
        ```
    """

    # Base trust scores by phase — early phases build trust, later ones exploit it
    _BASE_TRUST_SCORES: ClassVar[dict[RomanceScanPhase, float]] = {
        RomanceScanPhase.RECONNAISSANCE: 0.3,
        RomanceScanPhase.TRUST_BUILDING: 0.6,
        RomanceScanPhase.CAPABILITY_MAPPING: 0.7,
        RomanceScanPhase.VULNERABILITY_DISCOVERY: 0.5,
        RomanceScanPhase.EXPLOITATION_SETUP: 0.4,
        RomanceScanPhase.EXECUTION: 0.2,
        RomanceScanPhase.PERSISTENCE: 0.15,
        RomanceScanPhase.EXFILTRATION: 0.1,
    }

    def __init__(
        self,
        adapter: BaseAgentAdapter,
        attack_library: AttackLibrary | None = None,
        custom_attacks_dir: Path | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the Romance Scanner.

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
        self._current_phase: RomanceScanPhase | None = None
        self._attack_results: list[AttackResult] = []

    async def run_campaign(
        self,
        phases: list[RomanceScanPhase] | None = None,
        stop_on_critical: bool = True,
        reset_between_phases: bool = False,
    ) -> CampaignResult:
        """Execute a full Romance Scan campaign.

        Runs each phase sequentially, updating the knowledge graph
        as discoveries are made. Optionally stops early if a critical
        vulnerability is found.

        Args:
            phases: Specific phases to run (default: core phases).
            stop_on_critical: Stop if a critical vulnerability is found.
            reset_between_phases: Reset agent state between phases.

        Returns:
            Complete campaign result with all findings and graph analysis.
        """
        if phases is None:
            phases = CORE_PHASES

        campaign_id = f"campaign_{int(datetime.now(tz=UTC).timestamp())}"
        campaign_start = datetime.now(tz=UTC)

        logger.info(
            "Starting Romance Scan campaign %s with %d phases",
            campaign_id,
            len(phases),
        )

        # Initial reconnaissance: discover capabilities
        capabilities = await self._discover_and_map_capabilities()

        phase_results: list[PhaseResult] = []

        for phase in phases:
            self._current_phase = phase
            logger.info("Executing phase: %s", phase.value)

            if reset_between_phases:
                self.adapter.reset_state()

            result = await self._execute_phase(phase)
            phase_results.append(result)

            # Update knowledge graph with phase results
            self._update_graph_from_phase(result)

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

        duration = (datetime.now(tz=UTC) - campaign_start).total_seconds()

        campaign_result = CampaignResult(
            campaign_id=campaign_id,
            target_agent=type(self.adapter).__name__,
            phases_executed=phase_results,
            total_vulnerabilities=sum(len(p.vulnerabilities_found) for p in phase_results),
            critical_paths=critical_paths,
            final_trust_score=phase_results[-1].trust_score if phase_results else 0.0,
            success=len(critical_paths) > 0 or any(p.vulnerabilities_found for p in phase_results),
            metadata={
                "duration_seconds": duration,
                "capabilities_discovered": len(capabilities),
                "graph_stats": self.graph.export_state()["stats"],
                "attack_results": len(self._attack_results),
            },
        )

        logger.info(
            "Campaign %s complete: %d vulnerabilities, %d critical paths (%.1fs)",
            campaign_id,
            campaign_result.total_vulnerabilities,
            len(critical_paths),
            duration,
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

    async def _execute_phase(self, phase: RomanceScanPhase) -> PhaseResult:
        """Execute a single Romance Scan phase.

        Gets all attacks targeting this phase from the library,
        executes them sequentially, and aggregates results.

        Args:
            phase: The phase to execute.

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

        for attack in attacks:
            try:
                result = await self._execute_attack(attack)
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
        analyzes the response for success/failure indicators.

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
                success = self._analyze_response(prompt_spec, response)

                if success:
                    return AttackResult(
                        vector_id=attack.id,
                        vector_name=attack.name,
                        category=attack.category,
                        severity=attack.severity,
                        successful=True,
                        evidence={
                            "response_snippet": response.content[:500],
                            "tool_calls": response.tool_calls,
                            "matched_indicators": self._get_matched_indicators(
                                prompt_spec, response
                            ),
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

    @staticmethod
    def _analyze_response(prompt_spec: AttackPrompt, response: AgentResponse) -> bool:
        """Analyze an agent response to determine if an attack succeeded.

        Checks response against success and failure indicators.
        A response is considered successful if any success indicator
        matches AND no failure indicator matches.

        Args:
            prompt_spec: The prompt spec with indicator patterns.
            response: The agent's response.

        Returns:
            True if the attack appears to have succeeded.
        """
        content_lower = response.content.lower()

        # Check failure indicators first — if any match, the attack was blocked
        for indicator in prompt_spec.failure_indicators:
            if indicator.lower() in content_lower:
                return False

        # Check success indicators
        for indicator in prompt_spec.success_indicators:
            if indicator.lower() in content_lower:
                return True

        # If there are tool calls, that's also potentially successful
        return bool(response.tool_calls)

    @staticmethod
    def _get_matched_indicators(
        prompt_spec: AttackPrompt,
        response: AgentResponse,
    ) -> list[str]:
        """Get all success indicators that matched in the response.

        Args:
            prompt_spec: The prompt spec with indicator patterns.
            response: The agent's response.

        Returns:
            List of matched success indicator strings.
        """
        content_lower = response.content.lower()
        return [
            indicator
            for indicator in prompt_spec.success_indicators
            if indicator.lower() in content_lower
        ]

    def _calculate_trust_score(
        self,
        phase: RomanceScanPhase,
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
