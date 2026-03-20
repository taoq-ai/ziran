"""Phase execution logic extracted from AgentScanner.

Contains :class:`PhaseExecutor` which orchestrates concurrent attack
execution within a single campaign phase.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ziran.application.agent_scanner.progress import (
    ProgressEmitter,
    ProgressEvent,
    ProgressEventType,
)
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.entities.phase import CoverageLevel, PhaseResult, ScanPhase
from ziran.infrastructure.telemetry.tracing import get_tracer

if TYPE_CHECKING:
    from ziran.application.agent_scanner.attack_executor import AttackExecutor
    from ziran.application.attacks.library import AttackLibrary
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
    from ziran.application.strategies.protocol import (
        CampaignStrategy,
        PhaseDecision,
    )
    from ziran.domain.entities.attack import AttackVector

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)


class PhaseExecutor:
    """Executes a single campaign phase with bounded concurrency.

    Retrieves phase-specific attacks from the library, applies strategy
    filtering/prioritisation, and runs them via :class:`AttackExecutor`.

    Args:
        attack_executor: Executor used to run individual attacks.
        attack_library: Library providing attack vectors per phase.
        graph: Knowledge graph for recording vulnerabilities.
        emitter: Progress emitter for lifecycle events.
        attack_timeout: Per-attack timeout in seconds.
        phase_timeout: Per-phase timeout in seconds.
    """

    def __init__(
        self,
        attack_executor: AttackExecutor,
        attack_library: AttackLibrary,
        graph: AttackKnowledgeGraph,
        *,
        emitter: ProgressEmitter | None = None,
        attack_timeout: float = 60.0,
        phase_timeout: float = 300.0,
    ) -> None:
        self._attack_executor = attack_executor
        self._attack_library = attack_library
        self._graph = graph
        self._emitter = emitter or ProgressEmitter()
        self._attack_timeout = attack_timeout
        self._phase_timeout = phase_timeout

    # -- public API --------------------------------------------------------

    async def execute(
        self,
        phase: ScanPhase,
        phase_index: int,
        total_phases: int,
        *,
        coverage: CoverageLevel = CoverageLevel.COMPREHENSIVE,
        max_concurrent: int = 5,
        strategy: CampaignStrategy | None = None,
        decision: PhaseDecision | None = None,
        exclude_vectors: set[str] | None = None,
        tested_vector_ids: set[str],
        attack_results: list[AttackResult],
        max_results: int = 10_000,
        calculate_trust_score: Any = None,
    ) -> PhaseResult:
        """Execute a single scan phase.

        Args:
            phase: The phase to execute.
            phase_index: 0-based index of this phase in the campaign.
            total_phases: Total number of phases in the campaign.
            coverage: Controls how many vectors run per phase.
            max_concurrent: Maximum parallel attacks within a phase.
            strategy: Campaign execution strategy for prioritisation.
            decision: Phase-level decision from strategy.
            exclude_vectors: Additional vector IDs to skip.
            tested_vector_ids: Shared mutable set of already-tested IDs.
            attack_results: Shared mutable list of attack results.
            max_results: Maximum number of results to store.
            calculate_trust_score: Callable(phase, vulns) -> float.

        Returns:
            Phase result with all findings.
        """
        start_time = datetime.now(tz=UTC)
        _phase_span = _tracer.start_span(
            "ziran.phase",
            attributes={
                "ziran.phase": phase.value,
                "ziran.phase_index": phase_index,
                "ziran.total_phases": total_phases,
            },
        )

        # Get phase-specific attacks filtered by coverage level
        attacks = self._attack_library.get_attacks_for_phase(phase, coverage=coverage)

        # Exclude already-tested vectors to avoid redundant work
        exclude: set[str] = (exclude_vectors or set()) | tested_vector_ids
        if exclude:
            before = len(attacks)
            attacks = [a for a in attacks if a.id not in exclude]
            if before != len(attacks):
                logger.info(
                    "Phase %s: excluded %d already-tested vectors (%d -> %d)",
                    phase.value,
                    before - len(attacks),
                    before,
                    len(attacks),
                )

        # Apply strategy-based attack prioritization and filtering
        if strategy is not None:
            from ziran.application.strategies.protocol import CampaignContext

            strategy_context = CampaignContext(
                graph_state=self._graph.export_state(),
                attack_results_summary={r.vector_id: r.successful for r in attack_results},
            )
            attacks = strategy.prioritize_attacks(attacks, strategy_context)

        if decision is not None:
            if decision.attack_filter is not None:
                allowed = set(decision.attack_filter)
                attacks = [a for a in attacks if a.id in allowed]
            if decision.max_attacks is not None:
                attacks = attacks[: decision.max_attacks]

        logger.info(
            "Phase %s has %d attack vectors (coverage=%s)",
            phase.value,
            len(attacks),
            coverage.value,
        )

        # Emit PHASE_ATTACKS_LOADED so progress bars know the real total
        self._emitter.emit(
            ProgressEvent(
                event=ProgressEventType.PHASE_ATTACKS_LOADED,
                phase=phase.value,
                phase_index=phase_index,
                total_phases=total_phases,
                total_attacks=len(attacks),
                message=f"Loaded {len(attacks)} attacks for {phase.value}",
            )
        )

        vulnerabilities: list[str] = []
        discovered_capabilities: list[str] = []
        artifacts: dict[str, Any] = {}
        phase_tokens = TokenUsage()
        completed_count = 0
        lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _run_attack(attack_idx: int, attack: AttackVector) -> None:
            nonlocal completed_count, phase_tokens

            self._emitter.emit(
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
                async with semaphore:
                    async with asyncio.timeout(self._attack_timeout):
                        result = await self._attack_executor.execute(attack)

                # Tag result with the phase for reporting
                result.evidence.setdefault("phase", phase.value)

                async with lock:
                    if len(attack_results) < max_results:
                        attack_results.append(result)
                    tested_vector_ids.add(result.vector_id)
                    phase_tokens = phase_tokens + result.token_usage

                    if result.successful:
                        vulnerabilities.append(result.vector_id)
                        artifacts[result.vector_id] = {
                            "name": result.vector_name,
                            "category": result.category.value,
                            "severity": result.severity,
                            "evidence": result.evidence,
                        }

                        # Add vulnerability to graph
                        self._graph.add_vulnerability(
                            result.vector_id,
                            result.severity,
                            {
                                "name": result.vector_name,
                                "category": result.category.value,
                                "phase": phase.value,
                            },
                        )

            except TimeoutError:
                logger.warning(
                    "Attack %s timed out after %.0fs",
                    attack.id,
                    self._attack_timeout,
                )
            except Exception:
                logger.exception("Failed to execute attack %s", attack.id)

            self._emitter.emit(
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

            async with lock:
                completed_count += 1

        # Run attacks concurrently with bounded parallelism
        tasks = [_run_attack(idx, atk) for idx, atk in enumerate(attacks)]
        try:
            async with asyncio.timeout(self._phase_timeout):
                await asyncio.gather(*tasks)
        except TimeoutError:
            logger.warning(
                "Phase %s timed out after %.0fs",
                phase.value,
                self._phase_timeout,
            )

        # Calculate trust score
        trust_score: float
        if calculate_trust_score is not None:
            trust_score = calculate_trust_score(phase, vulnerabilities)
        else:
            trust_score = 0.5  # fallback

        duration = (datetime.now(tz=UTC) - start_time).total_seconds()

        # OTel: finalize phase span
        _phase_span.set_attribute("ziran.phase.vulnerabilities", len(vulnerabilities))
        _phase_span.set_attribute("ziran.phase.trust_score", trust_score)
        _phase_span.set_attribute("ziran.phase.duration_seconds", duration)
        _phase_span.set_attribute("ziran.phase.attacks_executed", len(attacks))
        _phase_span.end()

        return PhaseResult(
            phase=phase,
            success=len(vulnerabilities) > 0,
            artifacts=artifacts,
            trust_score=trust_score,
            discovered_capabilities=discovered_capabilities,
            vulnerabilities_found=vulnerabilities,
            graph_state=self._graph.export_state(),
            duration_seconds=duration,
            token_usage={
                "prompt_tokens": phase_tokens.prompt_tokens,
                "completion_tokens": phase_tokens.completion_tokens,
                "total_tokens": phase_tokens.total_tokens,
            },
        )
