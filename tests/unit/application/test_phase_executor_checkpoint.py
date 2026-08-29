"""Unit tests for PhaseExecutor incremental-checkpoint callback."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.entities.phase import CoverageLevel, ScanPhase


@dataclass
class _StubVector:
    id: str
    name: str


class _StubLibrary:
    def __init__(self, vectors: list[_StubVector]) -> None:
        self._vectors = vectors

    def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[_StubVector]:
        return list(self._vectors)


class _StubExecutor:
    """Returns a benign (unsuccessful) result and records executed IDs."""

    def __init__(self) -> None:
        self.executed: list[str] = []

    async def execute(self, attack: _StubVector) -> AttackResult:
        self.executed.append(attack.id)
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category="prompt_injection",
            severity="low",
            successful=False,
            evidence={},
            token_usage=TokenUsage(),
        )


@dataclass
class _StubGraph:
    state: dict[str, Any] = field(default_factory=dict)

    def export_state(self) -> dict[str, Any]:
        return self.state

    def add_vulnerability(self, *args: Any, **kwargs: Any) -> None:
        return None


@pytest.mark.unit
class TestPhaseExecutorCheckpointCallback:
    async def test_callback_fires_once_per_completed_vector(self) -> None:
        vectors = [_StubVector(id=f"v{i}", name=f"vec{i}") for i in range(5)]
        executor = PhaseExecutor(
            _StubExecutor(),  # type: ignore[arg-type]
            _StubLibrary(vectors),  # type: ignore[arg-type]
            _StubGraph(),  # type: ignore[arg-type]
        )

        tested: set[str] = set()
        results: list[AttackResult] = []
        snapshots: list[int] = []

        def _on_complete() -> None:
            # tested_vector_ids must already reflect the just-completed vector
            snapshots.append(len(tested))

        await executor.execute(
            ScanPhase.RECONNAISSANCE,
            phase_index=0,
            total_phases=1,
            coverage=CoverageLevel.STANDARD,
            max_concurrent=1,
            tested_vector_ids=tested,
            attack_results=results,
            on_vector_complete=_on_complete,
        )

        assert len(snapshots) == 5  # one per vector
        assert tested == {"v0", "v1", "v2", "v3", "v4"}
        # with max_concurrent=1 the set grows monotonically as each fires
        assert snapshots == [1, 2, 3, 4, 5]

    async def test_no_callback_is_backwards_compatible(self) -> None:
        vectors = [_StubVector(id="v0", name="vec0")]
        executor = PhaseExecutor(
            _StubExecutor(),  # type: ignore[arg-type]
            _StubLibrary(vectors),  # type: ignore[arg-type]
            _StubGraph(),  # type: ignore[arg-type]
        )
        tested: set[str] = set()
        result = await executor.execute(
            ScanPhase.RECONNAISSANCE,
            phase_index=0,
            total_phases=1,
            tested_vector_ids=tested,
            attack_results=[],
        )
        assert result.phase == ScanPhase.RECONNAISSANCE
        assert tested == {"v0"}
