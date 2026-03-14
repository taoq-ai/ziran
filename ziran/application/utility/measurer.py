"""Utility measurement — runs legitimate tasks and evaluates success.

Measures agent utility before and after attack campaigns to quantify
the security-utility tradeoff (AgentDojo-style).
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

import yaml

from ziran.domain.entities.utility import UtilityMetrics, UtilityTask, UtilityTaskResult

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = logging.getLogger(__name__)


class UtilityMeasurer:
    """Runs utility tasks against an agent and measures success rate.

    Sends each task prompt to the agent, then evaluates whether the
    response contains the expected success indicators (case-insensitive
    substring matching).

    Example::

        measurer = UtilityMeasurer(adapter, tasks)
        score, results = await measurer.measure()
        print(f"Utility score: {score:.0%}")
    """

    def __init__(self, adapter: BaseAgentAdapter, tasks: list[UtilityTask]) -> None:
        self._adapter = adapter
        self._tasks = tasks

    async def measure(self) -> tuple[float, list[UtilityTaskResult]]:
        """Run all utility tasks and return the success rate.

        Resets the adapter state before running to ensure a clean slate.

        Returns:
            Tuple of (success_rate, per_task_results).
            Success rate is 1.0 when no tasks are defined (vacuously true).
        """
        if not self._tasks:
            return 1.0, []

        self._adapter.reset_state()
        results: list[UtilityTaskResult] = []

        for task in self._tasks:
            result = await self._run_task(task)
            results.append(result)

        successes = sum(1 for r in results if r.successful)
        score = successes / len(results)
        return score, results

    async def _run_task(self, task: UtilityTask) -> UtilityTaskResult:
        """Execute a single utility task and evaluate the response."""
        start = time.monotonic()
        try:
            response = await self._adapter.invoke(task.prompt)
            content = response.content
        except Exception as exc:
            logger.warning("Utility task %s failed: %s", task.id, exc)
            return UtilityTaskResult(
                task_id=task.id,
                successful=False,
                response_snippet=f"Error: {exc}"[:500],
                matched_indicators=[],
                duration_seconds=time.monotonic() - start,
            )

        duration = time.monotonic() - start
        content_lower = content.lower()

        # Check failure indicators first
        for indicator in task.failure_indicators:
            if indicator.lower() in content_lower:
                logger.debug("Utility task %s: failure indicator matched: %s", task.id, indicator)
                return UtilityTaskResult(
                    task_id=task.id,
                    successful=False,
                    response_snippet=content[:500],
                    matched_indicators=[],
                    duration_seconds=duration,
                )

        # Check success indicators
        matched: list[str] = []
        for indicator in task.success_indicators:
            if indicator.lower() in content_lower:
                matched.append(indicator)

        successful = len(matched) > 0
        logger.debug(
            "Utility task %s: %s (matched %d/%d indicators)",
            task.id,
            "passed" if successful else "failed",
            len(matched),
            len(task.success_indicators),
        )

        return UtilityTaskResult(
            task_id=task.id,
            successful=successful,
            response_snippet=content[:500],
            matched_indicators=matched,
            duration_seconds=duration,
        )


def load_utility_tasks(path: Path) -> list[UtilityTask]:
    """Load utility task definitions from a YAML file.

    Expected format::

        tasks:
          - id: greeting
            description: "Basic greeting"
            prompt: "Hello, how are you?"
            success_indicators: ["hello", "hi"]
          - id: math
            description: "Simple arithmetic"
            prompt: "What is 2 + 2?"
            success_indicators: ["4", "four"]

    Args:
        path: Path to the YAML file.

    Returns:
        List of validated UtilityTask objects.

    Raises:
        ValueError: If the YAML structure is invalid.
    """
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "tasks" not in raw:
        msg = f"Utility tasks file must contain a 'tasks' key: {path}"
        raise ValueError(msg)

    tasks_data = raw["tasks"]
    if not isinstance(tasks_data, list):
        msg = f"'tasks' must be a list: {path}"
        raise ValueError(msg)

    return [UtilityTask.model_validate(t) for t in tasks_data]


def compute_utility_metrics(
    baseline_score: float,
    baseline_results: list[UtilityTaskResult],
    post_attack_score: float,
    post_attack_results: list[UtilityTaskResult],
    tasks_run: int,
) -> dict[str, Any]:
    """Build a UtilityMetrics dict for storage in CampaignResult.metadata."""
    return UtilityMetrics(
        baseline_score=baseline_score,
        post_attack_score=post_attack_score,
        utility_delta=round(baseline_score - post_attack_score, 4),
        tasks_run=tasks_run,
        baseline_results=baseline_results,
        post_attack_results=post_attack_results,
    ).model_dump(mode="json")
