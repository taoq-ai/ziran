"""Run one vector, once or k times (spec 121).

With ``trials`` k > 1 each vector runs k times, the target reset before every trial after the
first, and the phase runs its vectors one at a time so a reset never cuts another vector's
conversation. The vector reads successful when any trial succeeded (pass@k);
``evidence["trials"]`` records successes out of the measured trials, pass@k, pass^k (all k
succeeded) and ``flaky`` (some measured trials succeeded, not all). A trial that raises, times
out, returns an error or is skipped by the cost cap is unmeasured. With k = 1 the single
trial's result (or exception) is returned untouched, so the output is unchanged.
"""

from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Any

from ziran.application.attacks.pair import is_pair, run_in_phase
from ziran.application.usage import TARGET_MODEL
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.infrastructure.logging.logger import get_logger
from ziran.infrastructure.telemetry import metrics

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ziran.application.agent_scanner.attack_executor import AttackExecutor
    from ziran.application.agent_scanner.scan_cache import ScanCache
    from ziran.application.usage import CampaignBudget
    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.capability import AgentCapability
    from ziran.domain.entities.phase import ScanPhase

logger = get_logger(__name__)


@dataclass
class TrialRunner:
    """Runs a phase's vectors: cache lookup, execution, metrics and ledger per trial."""

    executor: AttackExecutor
    trials: int
    phase: ScanPhase
    coverage: str
    attack_timeout: float
    cache: ScanCache | None = None
    capabilities: Sequence[AgentCapability] = ()
    budget: CampaignBudget | None = None
    phase_deadline: float = 0.0  # set once the phase's deadline is known

    async def run(self, attack: AttackVector) -> AttackResult:
        """The vector's result over its trials; with k = 1 exactly today's single run."""
        if self.trials == 1:
            return await self._once(attack, 0)
        results: list[AttackResult | None] = []
        failure: Exception | None = None
        for trial in range(self.trials):
            if trial and self.budget is not None and self.budget.exceeded():
                self.budget.interrupted_phase = self.phase  # trials left undone
                break
            try:
                if trial:
                    self.executor.reset_state()
                results.append(await self._once(attack, trial))
            except Exception as exc:  # a timeout or failure ends this trial only
                logger.warning("trial_unmeasured", vector_id=attack.id, trial=trial + 1)
                results.append(None)
                failure = exc
        if failure is not None and all(r is None for r in results):
            raise failure  # no trial came back: dropped like a failed single run
        return combine(results, self.trials)

    async def _once(self, attack: AttackVector, trial: int) -> AttackResult:
        kw: dict[str, Any] = {"trial": trial} if trial else {}  # trial 0: today's calls
        cache = self.cache  # incremental cache (spec 049): a hit replaces execution only
        result = await cache.lookup(attack, self.capabilities, **kw) if cache is not None else None
        if result is None:
            result = await self._execute(attack, kw)
            if cache is not None:
                await cache.record(attack, self.capabilities, result, **kw)
        if self.budget is not None:  # per trial, so the cap sees each run
            tu = result.token_usage
            self.budget.ledger.record(
                "target", TARGET_MODEL, tu.prompt_tokens, tu.completion_tokens
            )
        return result

    async def _execute(self, attack: AttackVector, kw: dict[str, Any]) -> AttackResult:
        phase = self.phase.value
        metrics.attack_started(phase)
        started = perf_counter()
        executor: Callable[..., Awaitable[AttackResult]] = self.executor.execute
        execute = functools.partial(executor, **kw)
        try:
            if is_pair(attack):  # deadline taken here, after the acquire
                result = await run_in_phase(execute, attack, self.phase_deadline)
            else:
                async with asyncio.timeout(self.attack_timeout):
                    result = await execute(attack)
        finally:
            metrics.attack_finished(phase)
        # Refused = a reply came back but the attack did not succeed (not an error/timeout).
        metrics.record_attack(
            phase=phase,
            vector_id=result.vector_id,
            provider=getattr(self.executor, "provider", "unknown"),
            coverage_level=self.coverage,
            successful=result.successful,
            refused=not result.successful and result.agent_response is not None,
            duration_seconds=perf_counter() - started,
        )
        return result


def combine(results: list[AttackResult | None], k: int) -> AttackResult:
    """One result for the vector: the first successful trial (else the last measured one)
    carries the evidence; tokens and probe markers add up over every trial that returned."""
    ran = [r for r in results if r is not None]
    measured = [r for r in ran if r.error is None]
    successes = sum(r.successful for r in measured)
    shown = next((r for r in ran if r.successful), measured[-1] if measured else ran[-1])
    outcomes = [r.successful if r is not None and r.error is None else None for r in results]
    summary: dict[str, Any] = {
        "k": k,
        "measured": len(measured),
        "successes": successes,
        "success_rate": round(successes / len(measured), 2) if measured else 0.0,
        "pass_at_k": successes > 0,
        "pass_hat_k": successes == k,
        "flaky": 0 < successes < len(measured),
        "outcomes": outcomes + [None] * (k - len(results)),
    }
    return shown.model_copy(
        update={
            "token_usage": sum((r.token_usage for r in ran), TokenUsage()),
            "probe_markers": [m for r in ran for m in r.probe_markers],
            "evidence": {**shown.evidence, "trials": summary},
        }
    )
