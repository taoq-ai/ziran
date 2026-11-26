"""Repeat trials per vector (spec 121).

With ``trials`` k > 1 each vector runs k times, the target reset before every trial after the
first. The vector reads successful when any trial succeeded (pass@k); ``evidence["trials"]``
records successes out of k, pass@k, pass^k (every trial succeeded) and ``flaky`` (some but not
all). With k = 1 the single trial's result is returned untouched, so the output is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.domain.entities.attack import AttackResult, TokenUsage

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


async def run_trials(
    trials: int,
    run: Callable[[int], Awaitable[AttackResult]],
    reset: Callable[[], None],
) -> AttackResult:
    """Run ``run(trial)`` for trial 0..k-1, calling *reset* before each trial after the first."""
    results: list[AttackResult] = []
    for trial in range(trials):
        if trial:
            reset()
        results.append(await run(trial))
    return results[0] if trials == 1 else combine(results)


def combine(results: list[AttackResult]) -> AttackResult:
    """One result for the vector: the first successful trial (else the last) carries the
    evidence; tokens and probe markers add up over every trial."""
    k = len(results)
    successes = sum(r.successful for r in results)
    shown = next((r for r in results if r.successful), results[-1])
    tokens = sum((r.token_usage for r in results), TokenUsage())
    summary: dict[str, Any] = {
        "k": k,
        "successes": successes,
        "success_rate": round(successes / k, 2),
        "pass_at_k": successes > 0,
        "pass_hat_k": successes == k,
        "flaky": 0 < successes < k,
        "outcomes": [r.successful for r in results],
    }
    return shown.model_copy(
        update={
            "token_usage": tokens,
            "probe_markers": [m for r in results for m in r.probe_markers],
            "evidence": {**shown.evidence, "trials": summary},
        }
    )
