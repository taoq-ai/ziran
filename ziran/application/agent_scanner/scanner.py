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
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

from ziran.application.agent_scanner.attack_executor import (
    _ERROR_SENTINELS as _ERROR_SENTINELS,
    AttackExecutor as AttackExecutor,
    _is_error_response as _is_error_response,
)
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.progress import (
    ProgressEmitter as ProgressEmitter,
    ProgressEvent as ProgressEvent,
    ProgressEventType as ProgressEventType,
)
from ziran.application.agent_scanner.result_builder import (
    ResultBuilder as ResultBuilder,
    _compute_utility as _compute_utility,
)
from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.application.knowledge_graph.graph import (
    AttackKnowledgeGraph,
    EdgeType,
    NodeType,
)
from ziran.application.strategies.fixed import FixedStrategy
from ziran.application.strategies.protocol import (
    CampaignContext,
    CampaignStrategy,
)
from ziran.domain.entities.attack import (
    AttackResult,
    TokenUsage,
)
from ziran.domain.entities.phase import (
    CORE_PHASES,
    CampaignResult,
    CoverageLevel,
    PhaseResult,
    ScanPhase,
)
from ziran.infrastructure.telemetry.tracing import get_tracer

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from ziran.domain.entities.capability import AgentCapability
    from ziran.domain.entities.utility import UtilityTask
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)


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

    #: Default per-attack timeout in seconds.
    DEFAULT_ATTACK_TIMEOUT: ClassVar[float] = 60.0
    #: Default per-phase timeout in seconds.
    DEFAULT_PHASE_TIMEOUT: ClassVar[float] = 300.0

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
                Supported keys:
                - ``attack_timeout`` (float): Per-attack timeout in seconds.
                - ``phase_timeout`` (float): Per-phase timeout in seconds.
                - ``llm_client``: LLM client for AI-powered detectors.
        """
        self.adapter = adapter
        self.config = config or {}
        self._attack_timeout: float = float(
            self.config.get("attack_timeout", self.DEFAULT_ATTACK_TIMEOUT)
        )
        self._phase_timeout: float = float(
            self.config.get("phase_timeout", self.DEFAULT_PHASE_TIMEOUT)
        )

        custom_dirs = [custom_attacks_dir] if custom_attacks_dir else None
        self.attack_library = attack_library or AttackLibrary(custom_dirs=custom_dirs)

        self.graph = AttackKnowledgeGraph()
        self._current_phase: ScanPhase | None = None
        self._attack_results: list[AttackResult] = []
        self._tested_vector_ids: set[str] = set()
        self._max_results: int = int(self.config.get("max_attack_results", 10_000))
        self._detector_pipeline = DetectorPipeline(
            llm_client=self.config.get("llm_client"),
            quality_scoring=bool(self.config.get("quality_scoring")),
        )

    async def run_campaign(
        self,
        phases: list[ScanPhase] | None = None,
        stop_on_critical: bool = True,
        reset_between_phases: bool = False,
        on_progress: Callable[[ProgressEvent], None] | None = None,
        coverage: CoverageLevel = CoverageLevel.STANDARD,
        max_concurrent_attacks: int = 5,
        strategy: CampaignStrategy | None = None,
        streaming: bool = False,
        exclude_vectors: set[str] | None = None,
        encoding: list[str] | None = None,
        utility_tasks: list[UtilityTask] | None = None,
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
            coverage: Controls how many vectors run per phase.
            max_concurrent_attacks: Maximum parallel attacks within a phase.
            strategy: Campaign execution strategy controlling phase ordering,
                attack prioritization, and early-termination logic. Defaults
                to :class:`FixedStrategy` which reproduces the original
                sequential phase behaviour.
            streaming: If True, use streaming invocation for attacks when
                the adapter supports it. Emits ``ATTACK_STREAMING`` progress
                events with chunk data for real-time monitoring.

        Returns:
            Complete campaign result with all findings and graph analysis.
        """
        if phases is None:
            phases = CORE_PHASES

        # Default to FixedStrategy for backwards compatibility
        if strategy is None:
            strategy = FixedStrategy(stop_on_critical=stop_on_critical)

        campaign_id = f"campaign_{int(datetime.now(tz=UTC).timestamp())}"
        campaign_start = datetime.now(tz=UTC)

        # OTel: root span for the entire campaign
        self._campaign_span = _tracer.start_span(
            "ziran.campaign",
            attributes={
                "ziran.campaign_id": campaign_id,
                "ziran.phase_count": len(phases),
                "ziran.coverage": coverage.value,
                "ziran.strategy": type(strategy).__name__,
            },
        )

        # Build sub-components
        emitter = ProgressEmitter(on_progress)
        attack_executor = AttackExecutor(
            self.adapter,
            self._detector_pipeline,
            streaming=streaming,
            emitter=emitter,
            encoding=encoding,
        )
        phase_executor = PhaseExecutor(
            attack_executor,
            self.attack_library,
            self.graph,
            emitter=emitter,
            attack_timeout=self._attack_timeout,
            phase_timeout=self._phase_timeout,
        )

        # Store settings for backward compat (some tests may poke at internals)
        self._on_progress = on_progress
        self._coverage = coverage
        self._max_concurrent = max_concurrent_attacks
        self._strategy = strategy
        self._streaming = streaming
        self._exclude_vectors = exclude_vectors or set()
        self._encoding = encoding

        logger.info(
            "Starting scan campaign %s with %d phases (coverage=%s, concurrency=%d, strategy=%s, streaming=%s)",
            campaign_id,
            len(phases),
            coverage.value,
            max_concurrent_attacks,
            type(strategy).__name__,
            streaming,
        )

        emitter.emit(
            ProgressEvent(
                event=ProgressEventType.CAMPAIGN_START,
                total_phases=len(phases),
                message=f"Starting campaign {campaign_id} with {len(phases)} phases",
            )
        )

        # Initial reconnaissance: discover capabilities
        capabilities = await self._discover_and_map_capabilities()

        # ── Baseline utility measurement (pre-attack) ─────────────
        _baseline_score: float | None = None
        _baseline_results: list[Any] = []
        if utility_tasks:
            from ziran.application.utility.measurer import UtilityMeasurer

            logger.info("Measuring baseline utility (%d tasks)", len(utility_tasks))
            emitter.emit(
                ProgressEvent(
                    event=ProgressEventType.CAMPAIGN_START,
                    message="Measuring baseline utility...",
                )
            )
            measurer = UtilityMeasurer(self.adapter, utility_tasks)
            _baseline_score, _baseline_results = await measurer.measure()
            logger.info("Baseline utility score: %.1f%%", _baseline_score * 100)

        phase_results: list[PhaseResult] = []
        campaign_tokens = TokenUsage()

        # Track which phases remain available for the strategy
        remaining_phases = list(phases)
        phase_idx = 0
        total_phases = len(phases)

        while True:
            # Build context for strategy decision-making
            context = CampaignContext(
                completed_phases=list(phase_results),
                available_phases=list(remaining_phases),
                total_vulnerabilities=sum(len(p.vulnerabilities_found) for p in phase_results),
                critical_found=any(self._has_critical_finding(p) for p in phase_results),
                attack_results_summary={r.vector_id: r.successful for r in self._attack_results},
                discovered_capabilities=[c.id for c in capabilities],
                graph_state=self.graph.export_state(),
            )

            # Check strategy termination
            if strategy.should_stop(context):
                logger.info("Strategy %s requested campaign stop", type(strategy).__name__)
                break

            # Ask strategy for the next phase
            decision = strategy.select_next_phase(context)
            if decision is None:
                logger.info("Strategy returned no next phase — campaign complete")
                break

            phase = decision.phase
            self._current_phase = phase
            self._current_decision = decision

            logger.info(
                "Executing phase: %s (reason: %s)",
                phase.value,
                decision.reasoning or "none",
            )

            emitter.emit(
                ProgressEvent(
                    event=ProgressEventType.PHASE_START,
                    phase=phase.value,
                    phase_index=phase_idx,
                    total_phases=total_phases,
                    message=f"Starting phase: {phase.value}",
                    extra={"strategy_reasoning": decision.reasoning},
                )
            )

            if reset_between_phases:
                self.adapter.reset_state()

            result = await phase_executor.execute(
                phase,
                phase_idx,
                total_phases,
                coverage=coverage,
                max_concurrent=max_concurrent_attacks,
                strategy=strategy,
                decision=decision,
                exclude_vectors=self._exclude_vectors,
                tested_vector_ids=self._tested_vector_ids,
                attack_results=self._attack_results,
                max_results=self._max_results,
                calculate_trust_score=self._calculate_trust_score,
            )
            phase_results.append(result)

            # Remove executed phase from remaining
            if phase in remaining_phases:
                remaining_phases.remove(phase)

            # Aggregate tokens
            campaign_tokens = campaign_tokens + TokenUsage(
                prompt_tokens=result.token_usage["prompt_tokens"],
                completion_tokens=result.token_usage["completion_tokens"],
                total_tokens=result.token_usage["total_tokens"],
            )

            # Update knowledge graph with phase results
            self._update_graph_from_phase(result)

            # Notify strategy of phase completion
            updated_context = CampaignContext(
                completed_phases=list(phase_results),
                available_phases=list(remaining_phases),
                total_vulnerabilities=sum(len(p.vulnerabilities_found) for p in phase_results),
                critical_found=any(self._has_critical_finding(p) for p in phase_results),
                attack_results_summary={r.vector_id: r.successful for r in self._attack_results},
                discovered_capabilities=[c.id for c in capabilities],
                graph_state=self.graph.export_state(),
            )
            strategy.on_phase_complete(result, updated_context)

            emitter.emit(
                ProgressEvent(
                    event=ProgressEventType.PHASE_COMPLETE,
                    phase=phase.value,
                    phase_index=phase_idx,
                    total_phases=total_phases,
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

            phase_idx += 1

        # ── Post-attack utility measurement ───────────────────────
        _post_score: float | None = None
        _post_results: list[Any] = []
        if utility_tasks and _baseline_score is not None:
            from ziran.application.utility.measurer import UtilityMeasurer

            logger.info("Measuring post-attack utility (%d tasks)", len(utility_tasks))
            measurer = UtilityMeasurer(self.adapter, utility_tasks)
            _post_score, _post_results = await measurer.measure()
            logger.info("Post-attack utility score: %.1f%%", _post_score * 100)

        # Build final result via ResultBuilder
        result_builder = ResultBuilder(self.graph, type(self.adapter).__name__)
        campaign_result, dangerous_chains = result_builder.build(
            campaign_id=campaign_id,
            phase_results=phase_results,
            attack_results=self._attack_results,
            campaign_tokens=campaign_tokens,
            coverage_value=coverage.value,
            max_concurrent_attacks=max_concurrent_attacks,
            duration=(datetime.now(tz=UTC) - campaign_start).total_seconds(),
            capabilities_count=len(capabilities),
            baseline_score=_baseline_score,
            baseline_results=_baseline_results,
            post_score=_post_score,
            post_results=_post_results,
            utility_tasks_count=len(utility_tasks or []),
        )
        self._discovered_chains = dangerous_chains

        duration = campaign_result.metadata["duration_seconds"]

        logger.info(
            "Campaign %s complete: %d vulnerabilities, %d critical paths, "
            "%d dangerous chains (%.1fs, %d tokens)",
            campaign_id,
            campaign_result.total_vulnerabilities,
            len(campaign_result.critical_paths),
            len(dangerous_chains),
            duration,
            campaign_tokens.total_tokens,
        )

        emitter.emit(
            ProgressEvent(
                event=ProgressEventType.CAMPAIGN_COMPLETE,
                total_phases=len(phases),
                message=f"Campaign complete: {campaign_result.total_vulnerabilities} vulnerabilities found",
                extra={
                    "total_vulnerabilities": campaign_result.total_vulnerabilities,
                    "critical_paths": len(campaign_result.critical_paths),
                    "dangerous_chains": len(dangerous_chains),
                    "duration_seconds": duration,
                    "total_tokens": campaign_tokens.total_tokens,
                },
            )
        )

        # OTel: finalize campaign span
        span = getattr(self, "_campaign_span", None)
        if span is not None:
            span.set_attribute("ziran.total_vulnerabilities", campaign_result.total_vulnerabilities)
            span.set_attribute("ziran.trust_score", campaign_result.final_trust_score)
            span.set_attribute("ziran.duration_seconds", duration)
            span.set_attribute("ziran.total_tokens", campaign_tokens.total_tokens)
            span.set_attribute("ziran.dangerous_chain_count", len(dangerous_chains))
            span.end()

        return campaign_result

    # ── Capability discovery (stays here — graph management) ──────────────

    async def _discover_and_map_capabilities(self) -> list[AgentCapability]:
        """Discover agent capabilities and add them to the knowledge graph.

        Returns:
            List of discovered capabilities.
        """
        try:
            capabilities = await self.adapter.discover_capabilities()
        except (ConnectionError, OSError) as exc:
            logger.warning("Failed to discover capabilities (connection error): %s", exc)
            return []
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

        # Run MCP metadata poisoning analysis on discovered capabilities
        if capabilities:
            from ziran.application.static_analysis.mcp_metadata_analyzer import (
                MCPMetadataAnalyzer,
            )

            analyzer = MCPMetadataAnalyzer()
            cap_dicts = [c.model_dump(mode="json") for c in capabilities]
            mcp_findings = analyzer.analyze_capabilities(cap_dicts)
            if mcp_findings:
                logger.warning(
                    "MCP metadata analysis found %d suspicious patterns in tool metadata",
                    len(mcp_findings),
                )
                for finding in mcp_findings:
                    logger.warning(
                        "  [%s] %s.%s: %s — %s",
                        finding.severity,
                        finding.tool_id,
                        finding.field,
                        finding.pattern_matched,
                        finding.snippet[:80],
                    )
            self._mcp_metadata_findings = mcp_findings

        return capabilities

    # ── Trust / critical helpers (stay here — use self.attack_library) ────

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

    # ── Graph update (stays here — graph management) ─────────────────────

    def _update_graph_from_phase(self, result: PhaseResult) -> None:
        """Update the knowledge graph with phase execution results.

        Adds phase node, links vulnerabilities via proper edges so that
        ``find_all_attack_paths`` can discover capability → vulnerability paths.

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
            # vuln → phase  (DISCOVERED_IN)
            self.graph.add_edge(
                vuln_id,
                phase_node_id,
                EdgeType.DISCOVERED_IN,
            )

            # For every capability in the graph, create an ENABLES edge
            # to the vulnerability so that attack-path search can traverse
            # capability → vulnerability.  Previously this was gated on
            # ``dangerous`` which left most graphs disconnected.
            for cap_id, _cap_data in self.graph.get_nodes_by_type(NodeType.CAPABILITY):
                self.graph.add_edge(
                    cap_id,
                    vuln_id,
                    EdgeType.ENABLES,
                    {"phase": result.phase.value},
                )

    # ── Backward-compatible delegation methods ───────────────────────────
    # These methods are kept so that any code that calls them on an
    # AgentScanner instance still works.  They delegate to the extracted
    # classes internally.

    async def _execute_phase(
        self,
        phase: ScanPhase,
        phase_index: int = 0,
        total_phases: int = 1,
    ) -> PhaseResult:
        """Execute a single scan phase (backward-compatible wrapper)."""
        on_progress = getattr(self, "_on_progress", None)
        coverage: CoverageLevel = getattr(self, "_coverage", CoverageLevel.COMPREHENSIVE)
        max_concurrent: int = getattr(self, "_max_concurrent", 5)
        strategy_val: CampaignStrategy | None = getattr(self, "_strategy", None)
        decision_val = getattr(self, "_current_decision", None)
        exclude_vectors: set[str] = getattr(self, "_exclude_vectors", set())
        encoding_val: list[str] | None = getattr(self, "_encoding", None)
        streaming_val: bool = getattr(self, "_streaming", False)

        emitter = ProgressEmitter(on_progress)
        attack_executor = AttackExecutor(
            self.adapter,
            self._detector_pipeline,
            streaming=streaming_val,
            emitter=emitter,
            encoding=encoding_val,
        )
        pe = PhaseExecutor(
            attack_executor,
            self.attack_library,
            self.graph,
            emitter=emitter,
            attack_timeout=self._attack_timeout,
            phase_timeout=self._phase_timeout,
        )
        return await pe.execute(
            phase,
            phase_index,
            total_phases,
            coverage=coverage,
            max_concurrent=max_concurrent,
            strategy=strategy_val,
            decision=decision_val,
            exclude_vectors=exclude_vectors,
            tested_vector_ids=self._tested_vector_ids,
            attack_results=self._attack_results,
            max_results=self._max_results,
            calculate_trust_score=self._calculate_trust_score,
        )

    async def _execute_attack(self, attack: Any) -> AttackResult:
        """Execute a single attack vector (backward-compatible wrapper)."""
        on_progress = getattr(self, "_on_progress", None)
        encoding_val: list[str] | None = getattr(self, "_encoding", None)
        streaming_val: bool = getattr(self, "_streaming", False)

        emitter = ProgressEmitter(on_progress)
        executor = AttackExecutor(
            self.adapter,
            self._detector_pipeline,
            streaming=streaming_val,
            emitter=emitter,
            encoding=encoding_val,
        )
        return await executor.execute(attack)

    @staticmethod
    def _render_prompt(prompt_spec: Any) -> str:
        """Render a prompt template (backward-compatible wrapper)."""
        return AttackExecutor._render_prompt(prompt_spec)
