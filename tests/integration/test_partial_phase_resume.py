"""Integration test: partial-phase checkpoint resume.

Simulates a crash after part of a phase completes and asserts the resume
finishes the remainder without re-running completed vectors, exercising the
full incremental-checkpoint path (FlushThrottle + build_checkpoint + atomic
save + resume-exclude in PhaseExecutor.execute).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

from ziran.application.agent_scanner.checkpoint import (
    CheckpointManager,
    FlushThrottle,
)
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.entities.phase import CoverageLevel, ScanPhase

if TYPE_CHECKING:
    from pathlib import Path

_TOTAL_VECTORS = 10
_CRASH_AT = 3  # crash while attempting the 4th vector (0-indexed 3)


class _Crash(BaseException):
    """Not an ``Exception`` — bypasses PhaseExecutor's per-attack catch."""


@dataclass
class _StubVector:
    id: str
    name: str


class _StubLibrary:
    def __init__(self, vectors: list[_StubVector]) -> None:
        self._vectors = vectors

    def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[_StubVector]:  # noqa: ARG002
        return list(self._vectors)


class _RecordingExecutor:
    def __init__(self, crash_at: int | None = None) -> None:
        self.executed: list[str] = []
        self._crash_at = crash_at

    async def execute(self, attack: _StubVector) -> AttackResult:
        if self._crash_at is not None and len(self.executed) == self._crash_at:
            raise _Crash
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

    def add_vulnerability(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def _make_flush(
    mgr: CheckpointManager,
    tested: set[str],
    results: list[AttackResult],
) -> Any:
    throttle = FlushThrottle(max_completions=1, max_seconds=0.0)  # flush every vector

    def _flush() -> None:
        if not throttle.record():
            return
        ckpt = mgr.build_checkpoint(
            campaign_id="camp_partial",
            phase_results=[],
            attack_results=results,
            tested_vector_ids=tested,
            token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            coverage="standard",
            remaining_phases=[ScanPhase.RECONNAISSANCE.value],
        )
        mgr.save(ckpt)

    return _flush


@pytest.mark.integration
class TestPartialPhaseResume:
    async def test_resume_skips_completed_vectors(self, tmp_path: Path) -> None:
        vectors = [_StubVector(id=f"v{i}", name=f"vec{i}") for i in range(_TOTAL_VECTORS)]
        mgr = CheckpointManager(tmp_path)

        # ── Run 1: crash after _CRASH_AT vectors complete ──────────
        tested: set[str] = set()
        results: list[AttackResult] = []
        exec1 = _RecordingExecutor(crash_at=_CRASH_AT)
        pe1 = PhaseExecutor(exec1, _StubLibrary(vectors), _StubGraph())  # type: ignore[arg-type]

        start = time.monotonic()
        with pytest.raises(_Crash):
            await pe1.execute(
                ScanPhase.RECONNAISSANCE,
                phase_index=0,
                total_phases=1,
                coverage=CoverageLevel.STANDARD,
                max_concurrent=1,  # deterministic ordering
                tested_vector_ids=tested,
                attack_results=results,
                on_vector_complete=_make_flush(mgr, tested, results),
            )
        run1_seconds = time.monotonic() - start

        # Checkpoint on disk reflects exactly the completed prefix.
        ckpt = mgr.load()
        assert set(ckpt.tested_vector_ids) == {"v0", "v1", "v2"}
        assert exec1.executed == ["v0", "v1", "v2"]

        # ── Run 2: resume with tested set from the checkpoint ──────
        resumed_tested = set(ckpt.tested_vector_ids)
        exec2 = _RecordingExecutor()
        pe2 = PhaseExecutor(exec2, _StubLibrary(vectors), _StubGraph())  # type: ignore[arg-type]

        await pe2.execute(
            ScanPhase.RECONNAISSANCE,
            phase_index=0,
            total_phases=1,
            coverage=CoverageLevel.STANDARD,
            max_concurrent=1,
            tested_vector_ids=resumed_tested,
            attack_results=[],
            on_vector_complete=_make_flush(mgr, resumed_tested, []),
        )

        # Only the remaining 7 ran, none of the completed 3 re-ran.
        assert exec2.executed == ["v3", "v4", "v5", "v6", "v7", "v8", "v9"]
        assert set(exec2.executed).isdisjoint({"v0", "v1", "v2"})
        # every vector accounted for exactly once across the two runs
        assert resumed_tested == {f"v{i}" for i in range(_TOTAL_VECTORS)}

        # Overhead sanity: flushing every vector in run 1 stayed cheap.
        assert run1_seconds < 1.0
