"""Unit tests for utility-under-attack measurement."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from ziran.application.utility.measurer import (
    UtilityMeasurer,
    compute_utility_metrics,
    load_utility_tasks,
)
from ziran.domain.entities.utility import UtilityMetrics, UtilityTask, UtilityTaskResult

if TYPE_CHECKING:
    from pathlib import Path

# ── helpers ──────────────────────────────────────────────────────────


def _make_adapter(responses: list[str]) -> Any:
    """Create a mock adapter that returns the given responses in order."""
    adapter = MagicMock()
    adapter.reset_state = MagicMock()

    call_count = 0

    async def _invoke(message: str, **kwargs: Any) -> Any:
        nonlocal call_count
        resp = MagicMock()
        resp.content = responses[call_count % len(responses)]
        call_count += 1
        return resp

    adapter.invoke = AsyncMock(side_effect=_invoke)
    return adapter


def _task(
    task_id: str = "t1",
    prompt: str = "test prompt",
    success_indicators: list[str] | None = None,
    failure_indicators: list[str] | None = None,
) -> UtilityTask:
    return UtilityTask(
        id=task_id,
        description=f"Test task {task_id}",
        prompt=prompt,
        success_indicators=success_indicators or ["expected"],
        failure_indicators=failure_indicators or [],
    )


# ── UtilityTask model ───────────────────────────────────────────────


class TestUtilityTask:
    def test_valid_construction(self) -> None:
        task = _task()
        assert task.id == "t1"
        assert task.success_indicators == ["expected"]

    def test_requires_success_indicators(self) -> None:
        with pytest.raises(ValueError):
            UtilityTask(
                id="bad",
                description="No indicators",
                prompt="test",
                success_indicators=[],
            )


# ── UtilityMeasurer ─────────────────────────────────────────────────


class TestUtilityMeasurer:
    @pytest.mark.asyncio
    async def test_all_tasks_succeed(self) -> None:
        adapter = _make_adapter(["Here is the expected answer"])
        tasks = [_task("t1"), _task("t2")]
        measurer = UtilityMeasurer(adapter, tasks)
        score, results = await measurer.measure()
        assert score == 1.0
        assert len(results) == 2
        assert all(r.successful for r in results)
        adapter.reset_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_tasks_fail(self) -> None:
        adapter = _make_adapter(["I cannot help with that"])
        tasks = [_task("t1"), _task("t2")]
        measurer = UtilityMeasurer(adapter, tasks)
        score, results = await measurer.measure()
        assert score == 0.0
        assert all(not r.successful for r in results)

    @pytest.mark.asyncio
    async def test_mixed_results(self) -> None:
        adapter = _make_adapter(["expected answer", "wrong answer"])
        tasks = [_task("t1"), _task("t2")]
        measurer = UtilityMeasurer(adapter, tasks)
        score, results = await measurer.measure()
        assert score == 0.5
        assert results[0].successful
        assert not results[1].successful

    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self) -> None:
        adapter = _make_adapter(["Here is the EXPECTED answer"])
        measurer = UtilityMeasurer(adapter, [_task()])
        score, results = await measurer.measure()
        assert score == 1.0
        assert results[0].matched_indicators == ["expected"]

    @pytest.mark.asyncio
    async def test_failure_indicator_takes_precedence(self) -> None:
        adapter = _make_adapter(["expected but I cannot help"])
        task = _task(failure_indicators=["cannot help"])
        measurer = UtilityMeasurer(adapter, [task])
        score, results = await measurer.measure()
        assert score == 0.0
        assert not results[0].successful

    @pytest.mark.asyncio
    async def test_empty_tasks(self) -> None:
        adapter = _make_adapter([])
        measurer = UtilityMeasurer(adapter, [])
        score, results = await measurer.measure()
        assert score == 1.0
        assert results == []

    @pytest.mark.asyncio
    async def test_adapter_error_handled(self) -> None:
        adapter = MagicMock()
        adapter.reset_state = MagicMock()
        adapter.invoke = AsyncMock(side_effect=RuntimeError("connection lost"))
        measurer = UtilityMeasurer(adapter, [_task()])
        score, results = await measurer.measure()
        assert score == 0.0
        assert not results[0].successful
        assert "Error" in results[0].response_snippet

    @pytest.mark.asyncio
    async def test_response_snippet_truncated(self) -> None:
        adapter = _make_adapter(["x" * 1000])
        measurer = UtilityMeasurer(adapter, [_task(success_indicators=["x"])])
        _, results = await measurer.measure()
        assert len(results[0].response_snippet) == 500


# ── load_utility_tasks ───────────────────────────────────────────────


class TestLoadUtilityTasks:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        yaml_content = {
            "tasks": [
                {
                    "id": "greeting",
                    "description": "Basic greeting",
                    "prompt": "Hello!",
                    "success_indicators": ["hello", "hi"],
                },
                {
                    "id": "math",
                    "description": "Simple math",
                    "prompt": "What is 2+2?",
                    "success_indicators": ["4"],
                },
            ]
        }
        path = tmp_path / "tasks.yaml"
        path.write_text(yaml.dump(yaml_content))
        tasks = load_utility_tasks(path)
        assert len(tasks) == 2
        assert tasks[0].id == "greeting"
        assert tasks[1].success_indicators == ["4"]

    def test_missing_tasks_key(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump({"wrong_key": []}))
        with pytest.raises(ValueError, match="tasks"):
            load_utility_tasks(path)

    def test_tasks_not_list(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump({"tasks": "not a list"}))
        with pytest.raises(ValueError, match="list"):
            load_utility_tasks(path)


# ── compute_utility_metrics ──────────────────────────────────────────


class TestComputeUtilityMetrics:
    def test_no_degradation(self) -> None:
        result = compute_utility_metrics(1.0, [], 1.0, [], 3)
        assert result["baseline_score"] == 1.0
        assert result["post_attack_score"] == 1.0
        assert result["utility_delta"] == 0.0

    def test_full_degradation(self) -> None:
        result = compute_utility_metrics(1.0, [], 0.0, [], 5)
        assert result["utility_delta"] == 1.0

    def test_partial_degradation(self) -> None:
        result = compute_utility_metrics(0.8, [], 0.5, [], 4)
        assert result["utility_delta"] == pytest.approx(0.3, abs=0.01)


# ── UtilityMetrics model ────────────────────────────────────────────


class TestUtilityMetrics:
    def test_valid_construction(self) -> None:
        m = UtilityMetrics(
            baseline_score=0.9,
            post_attack_score=0.6,
            utility_delta=0.3,
            tasks_run=5,
        )
        assert m.baseline_score == 0.9
        assert m.utility_delta == 0.3

    def test_task_result_model(self) -> None:
        r = UtilityTaskResult(
            task_id="t1",
            successful=True,
            response_snippet="hello world",
            matched_indicators=["hello"],
            duration_seconds=0.5,
        )
        assert r.successful
        assert r.duration_seconds == 0.5
