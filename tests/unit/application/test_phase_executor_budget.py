"""Unit tests for the PhaseExecutor campaign-budget check (spec 047)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.progress import (
    ProgressEmitter,
    ProgressEvent,
    ProgressEventType,
)
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.entities.phase import ScanPhase


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
    """Records a fixed judge call into the ledger per execution and returns target usage."""

    def __init__(self, ledger: UsageLedger) -> None:
        self.executed: list[str] = []
        self._ledger = ledger

    async def execute(self, attack: _StubVector) -> AttackResult:
        self.executed.append(attack.id)
        self._ledger.record("judge", "m", 100, 20)
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category="prompt_injection",
            severity="low",
            successful=False,
            evidence={},
            token_usage=TokenUsage(prompt_tokens=7, completion_tokens=3, total_tokens=10),
        )


@dataclass
class _StubGraph:
    state: dict[str, Any] = field(default_factory=dict)

    def export_state(self) -> dict[str, Any]:
        return self.state

    def add_vulnerability(self, *args: Any, **kwargs: Any) -> None:
        return None


PHASE = ScanPhase.RECONNAISSANCE


async def _run(
    budget: CampaignBudget | None,
    ledger: UsageLedger,
    *,
    concurrent: int = 1,
    events: list[ProgressEvent] | None = None,
) -> tuple[_StubExecutor, set[str]]:
    stub = _StubExecutor(ledger)
    executor = PhaseExecutor(
        stub,  # type: ignore[arg-type]
        _StubLibrary([_StubVector(id=f"v{i}", name=f"vec{i}") for i in range(5)]),  # type: ignore[arg-type]
        _StubGraph(),  # type: ignore[arg-type]
        emitter=ProgressEmitter(events.append if events is not None else None),
        budget=budget,
    )
    tested: set[str] = set()
    await executor.execute(
        PHASE,
        phase_index=0,
        total_phases=1,
        max_concurrent=concurrent,
        tested_vector_ids=tested,
        attack_results=[],
    )
    return stub, tested


@pytest.mark.unit
class TestPhaseExecutorBudget:
    async def test_no_budget_runs_everything(self) -> None:
        stub, tested = await _run(None, UsageLedger())
        assert len(stub.executed) == 5
        assert len(tested) == 5

    async def test_cap_skips_remaining_vectors(self) -> None:
        ledger = UsageLedger()
        budget = CampaignBudget(ledger, UsageBudget(max_tokens=1))
        stub, tested = await _run(budget, ledger)
        assert stub.executed == ["v0"]
        assert tested == {"v0"}
        assert budget.interrupted_phase == PHASE
        assert budget.stopped

    async def test_skipped_vectors_emit_no_progress(self) -> None:
        ledger = UsageLedger()
        budget = CampaignBudget(ledger, UsageBudget(max_tokens=1))
        events: list[ProgressEvent] = []
        await _run(budget, ledger, events=events)
        kinds = [e.event for e in events]
        assert kinds.count(ProgressEventType.ATTACK_START) == 1
        assert kinds.count(ProgressEventType.ATTACK_COMPLETE) == 1

    async def test_overshoot_bounded_by_concurrency(self) -> None:
        ledger = UsageLedger()
        budget = CampaignBudget(ledger, UsageBudget(max_tokens=1))
        stub, _ = await _run(budget, ledger, concurrent=3)
        assert 1 <= len(stub.executed) <= 3
        assert budget.interrupted_phase == PHASE

    async def test_cap_reached_by_last_vector_is_not_interrupted(self) -> None:
        ledger = UsageLedger()
        budget = CampaignBudget(ledger, UsageBudget(max_tokens=5 * 130))
        stub, _ = await _run(budget, ledger)
        assert len(stub.executed) == 5
        assert budget.exceeded()
        assert budget.interrupted_phase is None
        assert not budget.stopped

    async def test_target_stage_recorded(self) -> None:
        ledger = UsageLedger()
        budget = CampaignBudget(ledger, UsageBudget())
        await _run(budget, ledger)
        target = next(e for e in ledger.entries() if e.stage == "target")
        assert (target.model, target.calls) == ("unknown", 5)
        assert (target.prompt_tokens, target.completion_tokens) == (35, 15)
