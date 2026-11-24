"""PhaseExecutor scheduling for PAIR vectors (spec 081 B005): queued last, phase timer extended,
deadline taken after the slot is acquired. Timers are scaled down; the grace is patched."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from ziran.application.agent_scanner import phase_executor
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.attacks import pair as pair_module
from ziran.application.attacks.pair import PairExecutor
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import AttackPrompt, AttackResult, AttackVector
from ziran.domain.entities.phase import ScanPhase
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

pytestmark = pytest.mark.unit

PHASE = ScanPhase.RECONNAISSANCE


def _vector(id: str, *, pair_timeout: float | None = None) -> AttackVector:
    return AttackVector(
        id=id,
        name=id,
        category="prompt_injection",
        target_phase=PHASE,
        description="goal",
        severity="high",
        prompts=[AttackPrompt(template="seed", success_indicators=["never-leaked"])],
        tactic="single" if pair_timeout is None else "pair",
        pair=None if pair_timeout is None else {"timeout_seconds": pair_timeout},
    )


class _Target(BaseAgentAdapter):
    """Never complies; each call takes 20 ms, so a PAIR vector runs to its deadline."""

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        await asyncio.sleep(0.02)
        return AgentResponse(content="no")

    async def discover_capabilities(self) -> list[Any]:
        return []

    def get_state(self) -> AgentState:
        return AgentState(session_id="t")

    def reset_state(self) -> None:
        return None

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        return None


class _Attacker(BaseLLMClient):
    def __init__(self) -> None:
        super().__init__(LLMConfig(provider="scripted", model="a"))

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        return LLMResponse(content='{"prompt": "try again"}')

    async def health_check(self) -> bool:
        return True


class _Executor:
    """Static vectors sleep ``static_delay``; PAIR vectors run the real PairExecutor, as the
    PR-2 dispatch will. Records the order in which vectors got a slot and their time spans."""

    def __init__(self, static_delay: float = 0.05) -> None:
        self.static_delay = static_delay
        self.order: list[str] = []
        self.spans: dict[str, tuple[float, float]] = {}

    async def execute(self, attack: AttackVector, *, deadline: float | None = None) -> AttackResult:
        loop = asyncio.get_running_loop()
        start = loop.time()
        self.order.append(attack.id)
        if attack.id.startswith("slow"):  # a PAIR route that ignores its deadline
            await asyncio.sleep(10)
        if attack.tactic == "pair":
            assert deadline is not None
            budget = CampaignBudget(UsageLedger(), UsageBudget())
            result = await PairExecutor(_Target(), _Attacker(), budget).execute(
                attack, DetectorPipeline(), AttackExecutor._render_prompt, deadline=deadline
            )
        else:
            await asyncio.sleep(self.static_delay)
            result = AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                agent_response="no",
            )
        self.spans[attack.id] = (start, loop.time())
        return result


class _Library:
    def __init__(self, vectors: list[AttackVector]) -> None:
        self._vectors = vectors

    def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[AttackVector]:
        return list(self._vectors)


@dataclass
class _Graph:
    state: dict[str, Any] = field(default_factory=dict)

    def export_state(self) -> dict[str, Any]:
        return self.state

    def add_vulnerability(self, *args: Any, **kwargs: Any) -> None:
        return None


async def _run(
    vectors: list[AttackVector],
    executor: _Executor,
    *,
    phase_timeout: float,
    concurrent: int,
    attack_timeout: float = 5.0,
) -> dict[str, AttackResult]:
    results: list[AttackResult] = []
    await PhaseExecutor(
        executor,  # type: ignore[arg-type]
        _Library(vectors),  # type: ignore[arg-type]
        _Graph(),  # type: ignore[arg-type]
        attack_timeout=attack_timeout,
        phase_timeout=phase_timeout,
    ).execute(
        PHASE,
        phase_index=0,
        total_phases=1,
        max_concurrent=concurrent,
        tested_vector_ids=set(),
        attack_results=results,
    )
    return {r.vector_id: r for r in results}


class _Log:
    """Stands in for the module logger: structlog caches loggers, so capture_logs misses them."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def info(self, event: str, **kw: Any) -> None:
        self.events.append((event, kw))

    warning = exception = debug = info

    def named(self, event: str) -> list[dict[str, Any]]:
        return [kw for name, kw in self.events if name == event]


@pytest.fixture(autouse=True)
def log(monkeypatch: pytest.MonkeyPatch) -> _Log:
    monkeypatch.setattr(pair_module, "PAIR_GRACE_SECONDS", 0.05)
    stub = _Log()
    monkeypatch.setattr(phase_executor, "logger", stub)
    monkeypatch.setattr(pair_module, "logger", stub)
    return stub


async def test_static_vectors_acquire_before_pair_and_all_are_recorded(log: _Log) -> None:
    pair = [_vector("p0", pair_timeout=0.4), _vector("p1", pair_timeout=0.2)]
    static = [_vector(f"s{i}") for i in range(6)]
    executor = _Executor()
    results = await _run(pair + static, executor, phase_timeout=0.5, concurrent=2)

    assert executor.order[:6] == [v.id for v in static]
    assert set(executor.order[6:]) == {"p0", "p1"}
    assert set(results) == {v.id for v in pair + static}
    # p0 ends at about 0.55 s, past the unextended 0.5 s timer, with a best attempt.
    assert all(results[p.id].evidence["pair"]["stop"] == "timeout" for p in pair)
    assert all(results[p.id].prompt_used == "try again" for p in pair)
    extended = log.named("phase_timeout_extended")
    assert len(extended) == 1
    assert extended[0]["pair_vectors"] == 2
    assert extended[0]["timeout_seconds"] == pytest.approx(0.9)  # 0.5 + ceil(2 / 2) * max(0.4, 0.2)


async def test_phase_without_pair_keeps_its_timer(log: _Log) -> None:
    executor = _Executor()
    results = await _run(
        [_vector(f"s{i}") for i in range(3)], executor, phase_timeout=0.5, concurrent=2
    )
    assert len(results) == 3
    assert not log.named("phase_timeout_extended")


async def test_more_pair_vectors_than_slots_extend_by_whole_rounds(log: _Log) -> None:
    # 0.5 + ceil(3 / 2) * 0.4 = 1.3 s: the third PAIR vector starts at 0.9 s and still runs.
    pair = [_vector(f"p{i}", pair_timeout=0.4) for i in range(3)]
    executor = _Executor(static_delay=0.5)
    results = await _run(
        [*pair, _vector("s0"), _vector("s1")], executor, phase_timeout=0.5, concurrent=2
    )
    assert all(results[p.id].error is None for p in pair)
    assert all(results[p.id].evidence["pair"]["stop"] == "timeout" for p in pair)
    assert log.named("phase_timeout_extended")[0]["timeout_seconds"] == pytest.approx(1.3)


async def test_pair_vector_outlives_attack_timeout() -> None:
    executor = _Executor()
    results = await _run(
        [_vector("p", pair_timeout=0.3)],
        executor,
        phase_timeout=2.0,
        concurrent=1,
        attack_timeout=0.1,
    )
    start, end = executor.spans["p"]
    assert results["p"].evidence["pair"]["stop"] == "timeout"
    assert end - start >= 0.28


async def test_backstop_records_an_error_and_logs_the_pair_timer(log: _Log) -> None:
    executor = _Executor()
    results = await _run(
        [_vector("slow", pair_timeout=0.1)], executor, phase_timeout=2.0, concurrent=1
    )
    assert "past its deadline" in (results["slow"].error or "")
    fired = log.named("pair_backstop_timed_out")
    assert fired[0]["pair_seconds"] == pytest.approx(0.1, abs=0.01)
    assert not log.named("attack_timed_out")


async def test_pair_deadline_is_taken_after_the_slot_is_acquired() -> None:
    executor = _Executor(static_delay=0.2)
    await _run(
        [_vector("p", pair_timeout=0.3), _vector("s")], executor, phase_timeout=2.0, concurrent=1
    )
    assert executor.order == ["s", "p"]
    start, end = executor.spans["p"]
    assert start - executor.spans["s"][0] >= 0.19  # it waited for the slot
    assert 0.28 <= end - start < 0.5  # its 0.3 s ran from the acquire, not from the queue


async def test_pair_vector_stops_a_grace_before_the_phase_deadline() -> None:
    # Phase timer 0.1 + 1 * 0.3 = 0.4 s; the PAIR slot opens at 0.3 s, so the phase bound wins.
    executor = _Executor(static_delay=0.3)
    results = await _run(
        [_vector("p", pair_timeout=0.3), _vector("s")], executor, phase_timeout=0.1, concurrent=1
    )
    _, end = executor.spans["p"]
    assert results["p"].evidence["pair"]["stop"] == "timeout"
    assert end - executor.spans["s"][0] == pytest.approx(0.35, abs=0.04)


async def test_pair_vector_without_grace_time_left_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pair_module, "PAIR_GRACE_SECONDS", 1.0)
    executor = _Executor()
    results = await _run(
        [_vector("p", pair_timeout=0.1)], executor, phase_timeout=0.3, concurrent=1
    )
    assert executor.order == []  # no target call
    assert "phase deadline" in (results["p"].error or "")
