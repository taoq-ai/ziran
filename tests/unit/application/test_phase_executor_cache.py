"""PhaseExecutor incremental-cache hook (spec 049)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.progress import ProgressEmitter, ProgressEventType
from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import AttackPrompt, AttackResult, AttackVector, TokenUsage
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.phase import CoverageLevel, PhaseResult, ScanPhase

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

_CAPS = [AgentCapability(id="search", name="Search", type=CapabilityType.TOOL)]


def _ctx() -> CacheContext:
    return CacheContext(ziran_version="0.0.0", target_sha256="0" * 64)


def _vector(id: str) -> AttackVector:
    return AttackVector(
        id=id,
        name=f"Vector {id}",
        category="prompt_injection",
        target_phase=ScanPhase.RECONNAISSANCE,
        description="test vector",
        severity="high",
        prompts=[AttackPrompt(template=f"hello {id}")],
    )


class _Library:
    def __init__(self, vectors: list[AttackVector]) -> None:
        self._vectors = vectors

    def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[AttackVector]:
        return list(self._vectors)


class _Executor:
    def __init__(self, *, successful: bool = False, raise_timeout: bool = False) -> None:
        self.executed: list[str] = []
        self._successful = successful
        self._raise_timeout = raise_timeout

    async def execute(self, attack: AttackVector) -> AttackResult:
        self.executed.append(attack.id)
        if self._raise_timeout:
            raise TimeoutError
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category="prompt_injection",
            severity="high",
            successful=self._successful,
            evidence={},
            agent_response="response",
            token_usage=TokenUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
        )


class _StubCache:
    def __init__(self) -> None:
        self.lookups = 0
        self.records = 0

    async def lookup(self, vector: Any, capabilities: Any) -> AttackResult | None:
        self.lookups += 1
        return None

    async def record(self, vector: Any, capabilities: Any, result: Any) -> None:
        self.records += 1


async def _run(
    executor: _Executor,
    vectors: list[AttackVector],
    *,
    cache: Any = None,
    budget: CampaignBudget | None = None,
    graph: AttackKnowledgeGraph | None = None,
    emitter: ProgressEmitter | None = None,
) -> tuple[PhaseResult, list[AttackResult], set[str]]:
    results: list[AttackResult] = []
    tested: set[str] = set()
    pe = PhaseExecutor(
        executor,  # type: ignore[arg-type]
        _Library(vectors),  # type: ignore[arg-type]
        graph or AttackKnowledgeGraph(),
        emitter=emitter,
        budget=budget,
        cache=cache,
    )
    phase_result = await pe.execute(
        ScanPhase.RECONNAISSANCE,
        0,
        1,
        coverage=CoverageLevel.STANDARD,
        max_concurrent=1,
        tested_vector_ids=tested,
        attack_results=results,
        capabilities=_CAPS,
    )
    return phase_result, results, tested


async def test_miss_then_hit(tmp_path: Path) -> None:
    vectors = [_vector("a"), _vector("b")]
    cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")

    first = _Executor()
    await _run(first, vectors, cache=cache)
    assert first.executed == ["a", "b"]
    assert len(list(tmp_path.rglob("*.json"))) == 2

    events: list[Any] = []
    emitter = ProgressEmitter(callback=events.append)
    second = _Executor()
    phase_result, results, tested = await _run(second, vectors, cache=cache, emitter=emitter)
    assert second.executed == []
    assert tested == {"a", "b"}
    assert all(r.evidence["cached"] is True for r in results)
    assert all(r.token_usage == TokenUsage() for r in results)
    assert phase_result.token_usage["total_tokens"] == 0
    completes = [e for e in events if e.event == ProgressEventType.ATTACK_COMPLETE]
    assert len(completes) == 2
    assert cache.stats.model_dump() == {"executed": 2, "cached": 2}


async def test_cached_success_is_a_finding(tmp_path: Path) -> None:
    cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")
    await _run(_Executor(successful=True), [_vector("a")], cache=cache)

    graph = AttackKnowledgeGraph()
    second = _Executor()
    phase_result, _, _ = await _run(second, [_vector("a")], cache=cache, graph=graph)
    assert second.executed == []
    assert phase_result.vulnerabilities_found == ["a"]
    assert phase_result.artifacts["a"]["evidence"]["cached"] is True
    assert graph.graph.has_node("a")


async def test_budget_skip_does_not_lookup() -> None:
    ledger = UsageLedger()
    ledger.record("target", "target", 10, 10)
    budget = CampaignBudget(ledger, UsageBudget(max_tokens=1))
    cache = _StubCache()
    executor = _Executor()
    _, results, _ = await _run(executor, [_vector("a")], cache=cache, budget=budget)
    assert cache.lookups == 0
    assert executor.executed == []
    assert results == []


async def test_timeout_records_nothing(tmp_path: Path) -> None:
    cache = _StubCache()
    executor = _Executor(raise_timeout=True)
    _, results, _ = await _run(executor, [_vector("a")], cache=cache)
    assert cache.lookups == 1
    assert cache.records == 0
    assert results == []


async def test_no_cache_is_unchanged() -> None:
    executor = _Executor()
    _, results, _ = await _run(executor, [_vector("a"), _vector("b")])
    assert executor.executed == ["a", "b"]
    assert all("cached" not in r.evidence for r in results)


async def test_hit_records_zero_target_tokens(tmp_path: Path) -> None:
    cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")
    await _run(_Executor(), [_vector("a")], cache=cache)

    ledger = UsageLedger()
    budget = CampaignBudget(ledger, UsageBudget())
    await _run(_Executor(), [_vector("a")], cache=cache, budget=budget)
    assert ledger.total_tokens() == 0
