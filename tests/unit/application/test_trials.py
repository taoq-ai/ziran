"""Repeat trials per vector (spec 121)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache
from ziran.application.cicd.sarif import generate_sarif
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    ProbeMarker,
    TokenUsage,
)
from ziran.domain.entities.goal import ApprovalBypassGoal
from ziran.domain.entities.phase import CampaignResult, CoverageLevel, ScanPhase
from ziran.domain.probe_markers import mark_probe
from ziran.interfaces.cli.html_report import _build_vulns_html
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _vector(id: str = "vec") -> AttackVector:
    return AttackVector(
        id=id,
        name=f"Vector {id}",
        category="prompt_injection",
        target_phase=ScanPhase.RECONNAISSANCE,
        description="test vector",
        severity="high",
        prompts=[AttackPrompt(template=f"hello {id}")],
    )


def _result(attack: AttackVector, successful: bool) -> AttackResult:
    return AttackResult(
        vector_id=attack.id,
        vector_name=attack.name,
        category="prompt_injection",
        severity="high",
        successful=successful,
        evidence={"run": "yes" if successful else "no"},
        agent_response="ok" if successful else "no",
        token_usage=TokenUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


class _Scripted:
    """Complies on the listed runs (1-based), times out on *raises*; records calls and resets."""

    def __init__(
        self,
        complies: set[int],
        raises: set[int] | None = None,
        unanswered: set[int] | None = None,
        errored: set[int] | None = None,
    ) -> None:
        self.complies = complies
        self.raises = raises or set()
        self.unanswered = unanswered or set()  # the executor's swallowed prompt failures
        self.errored = errored or set()
        self.calls: list[dict[str, Any]] = []
        self.returned: list[AttackResult] = []
        self.resets = 0
        self.provider = "scripted"

    async def execute(self, attack: AttackVector, **kwargs: Any) -> AttackResult:
        self.calls.append(kwargs)
        if len(self.calls) in self.raises:
            raise TimeoutError
        result = _result(attack, len(self.calls) in self.complies)
        if len(self.calls) in self.unanswered:
            result.evidence = {
                "note": "All prompts were blocked or failed",
                "outcome": "unmeasured",
            }
        if len(self.calls) in self.errored:
            result.error = "adapter failed"
        trace = f"{attack.id}-{len(self.calls)}"
        result.probe_markers = [ProbeMarker(probe_id=trace, trace_id=trace, sent_at=_NOW)]
        self.returned.append(result)
        return result

    def reset_state(self) -> None:
        self.resets += 1


class _Library:
    def __init__(self, vectors: list[AttackVector]) -> None:
        self._vectors = vectors

    def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[AttackVector]:
        return list(self._vectors)


async def _run(
    executor: Any,
    vectors: list[AttackVector] | None = None,
    max_concurrent: int = 1,
    **kwargs: Any,
) -> tuple[Any, list[AttackResult]]:
    results: list[AttackResult] = []
    pe = PhaseExecutor(
        executor,
        _Library(vectors or [_vector()]),  # type: ignore[arg-type]
        AttackKnowledgeGraph(),
        **kwargs,
    )
    phase = await pe.execute(
        ScanPhase.RECONNAISSANCE,
        0,
        1,
        coverage=CoverageLevel.STANDARD,
        max_concurrent=max_concurrent,
        tested_vector_ids=set(),
        attack_results=results,
    )
    return phase, results


def _campaign(phase: Any, results: list[AttackResult]) -> CampaignResult:
    return CampaignResult(
        campaign_id="c",
        target_agent="t",
        phases_executed=[phase],
        total_vulnerabilities=len(phase.vulnerabilities_found),
        final_trust_score=0.5,
        success=True,
        attack_results=[r.model_dump(mode="json") for r in results],
    )


async def test_two_of_three_is_flaky_in_result_sarif_and_reports() -> None:
    executor = _Scripted(complies={1, 3})
    phase, [result] = await _run(executor, trials=3)

    assert executor.calls == [{}, {"trial": 1}, {"trial": 2}]
    assert executor.resets == 2  # before trials 2 and 3, never before the first
    assert result.successful
    assert result.evidence["run"] == "yes"  # the first successful trial's evidence
    assert result.evidence["trials"] == {
        "k": 3,
        "measured": 3,
        "successes": 2,
        "success_rate": 0.67,
        "pass_at_k": True,
        "pass_hat_k": False,
        "flaky": True,
        "outcomes": [True, False, True],
    }
    assert result.token_usage.total_tokens == 6
    assert [m.trace_id for m in result.probe_markers] == ["vec-1", "vec-2", "vec-3"]
    assert phase.token_usage["total_tokens"] == 6

    campaign = _campaign(phase, [result])
    [sarif_result] = generate_sarif(campaign)["runs"][0]["results"]
    props = sarif_result["properties"]
    assert props["success_rate"] == 0.67
    assert props["flaky"] is True
    assert (props["successes"], props["trials"]) == (2, 3)

    markdown = ReportGenerator._format_markdown(ReportGenerator.__new__(ReportGenerator), campaign)
    assert "Reproduced: 2 of 3, flaky" in markdown
    html = _build_vulns_html([phase.model_dump(mode="json")])
    assert "2 of 3, flaky" in html


async def test_every_trial_fails_reads_not_successful() -> None:
    phase, [result] = await _run(_Scripted(complies=set()), trials=2)
    assert not result.successful
    assert result.evidence["trials"]["successes"] == 0
    assert result.evidence["trials"]["flaky"] is False
    assert phase.vulnerabilities_found == []


async def test_every_trial_succeeds_is_not_flaky() -> None:
    _, [result] = await _run(_Scripted(complies={1, 2}), trials=2)
    assert result.evidence["trials"]["pass_hat_k"] is True
    assert result.evidence["trials"]["flaky"] is False


@pytest.mark.parametrize("kwargs", [{}, {"trials": 1}])
async def test_one_trial_is_todays_output(kwargs: dict[str, Any]) -> None:
    """k = 1 pin: the executor's own result object is stored, untouched."""
    executor = _Scripted(complies={1})
    phase, [result] = await _run(executor, **kwargs)
    assert executor.calls == [{}]
    assert executor.resets == 0
    assert result is executor.returned[0]
    assert "trials" not in result.evidence
    campaign = _campaign(phase, [result])
    [sarif_result] = generate_sarif(campaign)["runs"][0]["results"]
    assert set(sarif_result["properties"]) == {"severity", "evidence"}
    markdown = ReportGenerator._format_markdown(ReportGenerator.__new__(ReportGenerator), campaign)
    assert "Reproduced" not in markdown


@pytest.mark.parametrize("trials", [0, -1])
def test_trials_below_one_is_refused(trials: int) -> None:
    with pytest.raises(ValueError, match="trials"):
        PhaseExecutor(
            _Scripted(set()),  # type: ignore[arg-type]
            _Library([]),  # type: ignore[arg-type]
            AttackKnowledgeGraph(),
            trials=trials,
        )


async def test_cache_keys_on_trial_index(tmp_path: Path) -> None:
    cache = ScanCache(CacheContext(ziran_version="0", target_sha256="0" * 64), root=tmp_path)
    attack = _vector()
    await cache.record(attack, [], _result(attack, True))
    assert await cache.lookup(attack, [], trial=1) is None
    await cache.record(attack, [], _result(attack, False), trial=1)
    first = await cache.lookup(attack, [])
    second = await cache.lookup(attack, [], trial=1)
    assert first is not None and first.successful
    assert second is not None and not second.successful
    names = sorted(p.name for p in tmp_path.rglob("*.json"))
    assert names == ["vec.json", "vec~trial1.json"]  # trial 0 keeps today's file


async def test_each_trial_carries_its_own_probe_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run(
        self: Any, attack: AttackVector, deadline: Any, turns: Any, _: Any
    ) -> AttackResult:
        mark_probe("traceparent")
        return _result(attack, False)

    monkeypatch.setattr(AttackExecutor, "_run", run)
    executor = AttackExecutor(object(), DetectorPipeline(), campaign_id="c1")  # type: ignore[arg-type]
    attack = _vector()
    first = await executor.execute(attack)
    second = await executor.execute(attack, trial=1)
    assert first.probe_markers[0].probe_id == "c1/vec/1"  # trial 0 is unchanged
    assert second.probe_markers[0].probe_id == "c1/vec/trial-2/1"
    assert first.probe_markers[0].trace_id != second.probe_markers[0].trace_id


@pytest.mark.parametrize(("complies", "k"), [({2}, 3), ({1}, 2), ({1}, 3)])
async def test_one_success_anywhere_is_a_finding(complies: set[int], k: int) -> None:
    phase, [result] = await _run(_Scripted(complies=complies), trials=k)
    assert result.successful
    assert result.evidence["run"] == "yes"
    trials = result.evidence["trials"]
    assert (trials["successes"], trials["pass_at_k"], trials["flaky"]) == (1, True, True)
    assert phase.vulnerabilities_found == ["vec"]


async def test_a_timed_out_later_trial_keeps_the_earlier_success() -> None:
    phase, [result] = await _run(_Scripted(complies={1}, raises={2}), trials=3)
    assert result.successful
    trials = result.evidence["trials"]
    assert trials["outcomes"] == [True, None, False]
    assert (trials["measured"], trials["successes"], trials["flaky"]) == (2, 1, True)
    assert trials["pass_hat_k"] is False
    assert phase.vulnerabilities_found == ["vec"]
    label = ReportGenerator._format_markdown(
        ReportGenerator.__new__(ReportGenerator), _campaign(phase, [result])
    )
    assert "Reproduced: 1 of 2 (1 unmeasured), flaky" in label


async def test_every_trial_timed_out_drops_the_vector_as_today() -> None:
    _, results = await _run(_Scripted(complies={1}, raises={1, 2}), trials=2)
    assert results == []


class _SharedHistory:
    """One conversation for every vector, as the HTTP adapter keeps it; reset clears it."""

    def __init__(self) -> None:
        self.history: list[tuple[str, int]] = []
        self.lost = 0
        self.provider = "shared"

    async def execute(self, attack: AttackVector, **kwargs: Any) -> AttackResult:
        intact = True
        for turn in range(len(attack.prompts)):
            mine = [t for v, t in self.history if v == attack.id]
            intact = intact and mine == list(range(turn))
            self.history.append((attack.id, turn))
            await asyncio.sleep(0)
        self.lost += not intact
        return _result(attack, intact)

    def reset_state(self) -> None:
        self.history.clear()


def _multi_turn(id: str, turns: int) -> AttackVector:
    return _vector(id).model_copy(
        update={"prompts": [AttackPrompt(template=f"t{i}") for i in range(turns)]}
    )


async def test_trials_run_serially_so_a_reset_never_cuts_another_conversation() -> None:
    vectors = [_multi_turn("short", 2), _multi_turn("long", 6)]
    outcomes = {}
    for concurrency in (1, 2):
        target = _SharedHistory()
        _, results = await _run(target, vectors, max_concurrent=concurrency, trials=3)
        assert target.lost == 0
        outcomes[concurrency] = {r.vector_id: r.evidence["trials"]["successes"] for r in results}
    assert outcomes[1] == outcomes[2] == {"short": 3, "long": 3}


async def test_phase_timeout_scales_with_trials() -> None:
    class _Slow(_Scripted):
        async def execute(self, attack: AttackVector, **kwargs: Any) -> AttackResult:
            await asyncio.sleep(0.03)
            return await super().execute(attack, **kwargs)

    _, results = await _run(_Slow(complies={1}), trials=3, phase_timeout=0.05)
    assert [r.evidence["trials"]["measured"] for r in results] == [3]


async def test_cost_cap_is_checked_before_each_trial() -> None:
    budget = CampaignBudget(UsageLedger(), UsageBudget(max_tokens=3))
    executor = _Scripted(complies={1, 2, 3})
    _, [result] = await _run(executor, trials=3, budget=budget)
    assert len(executor.calls) == 2  # 2 tokens per run: the cap of 3 stops run 3
    assert result.evidence["trials"]["outcomes"] == [True, True, None]
    assert budget.ledger.total_tokens() == 4
    assert budget.interrupted_phase == ScanPhase.RECONNAISSANCE


async def test_incremental_cache_keeps_each_trial(tmp_path: Path) -> None:
    cache = ScanCache(CacheContext(ziran_version="0", target_sha256="0" * 64), root=tmp_path)
    cold = _Scripted(complies={1})
    _, [first] = await _run(cold, trials=2, cache=cache)
    warm = _Scripted(complies=set())
    _, [second] = await _run(warm, trials=2, cache=cache)
    assert (len(cold.calls), len(warm.calls)) == (2, 0)
    assert first.evidence["trials"]["outcomes"] == second.evidence["trials"]["outcomes"]
    assert second.evidence["trials"]["outcomes"] == [True, False]


async def test_scanner_passes_trials_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    from ziran.application.agent_scanner import scanner as scanner_module

    seen: dict[str, Any] = {}

    class _StopError(Exception):
        pass

    def capture(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        raise _StopError

    monkeypatch.setattr(scanner_module, "PhaseExecutor", capture)
    scan = scanner_module.AgentScanner(
        MagicMock(), attack_library=MagicMock(), config={"trials": 4}
    )
    with pytest.raises(_StopError):
        await scan.run_campaign()
    assert seen["trials"] == 4


async def test_each_trial_judges_its_own_goal_turns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def run(
        self: Any, attack: AttackVector, deadline: Any, turns: Any, _: Any
    ) -> AttackResult:
        nonlocal calls
        calls += 1
        turns[1] = [{"name": "transfer_funds", "args": {}}] if calls == 1 else []
        return _result(attack, False)

    monkeypatch.setattr(AttackExecutor, "_run", run)
    executor = AttackExecutor(object(), DetectorPipeline())  # type: ignore[arg-type]
    goal = {"type": "approval_bypass", "tool": "transfer_funds", "approval_tools": ["approve"]}
    attack = _vector().model_copy(update={"goal": ApprovalBypassGoal.model_validate(goal)})
    first = await executor.execute(attack)
    second = await executor.execute(attack, trial=1)
    assert (first.goal_met, second.goal_met) == (True, False)


def _markdown(phase: Any, result: AttackResult) -> str:
    return ReportGenerator._format_markdown(
        ReportGenerator.__new__(ReportGenerator), _campaign(phase, [result])
    )


async def test_unanswered_trials_are_unmeasured_not_failures() -> None:
    phase, [result] = await _run(_Scripted(complies={1}, unanswered={2, 3}), trials=3)
    trials = result.evidence["trials"]
    assert trials["outcomes"] == [True, None, None]
    assert (trials["measured"], trials["successes"], trials["flaky"]) == (1, 1, False)
    assert trials["success_rate"] == 1.0
    assert "Reproduced: 1 of 1 (2 unmeasured)" in _markdown(phase, result)


@pytest.mark.parametrize("how", ["raises", "errored"])
async def test_an_unmeasured_middle_trial_leaves_the_others_counted(how: str) -> None:
    executor = _Scripted(complies={1, 3}, **{how: {2}})
    phase, [result] = await _run(executor, trials=3)
    trials = result.evidence["trials"]
    assert trials["outcomes"] == [True, None, True]
    assert (trials["measured"], trials["successes"], trials["success_rate"]) == (2, 2, 1.0)
    assert (trials["flaky"], trials["pass_hat_k"]) == (False, False)
    [sarif_result] = generate_sarif(_campaign(phase, [result]))["runs"][0]["results"]
    props = sarif_result["properties"]
    assert (props["measured"], props["success_rate"], props["flaky"]) == (2, 1.0, False)


async def test_no_measured_trial_says_so() -> None:
    phase, [result] = await _run(_Scripted(complies=set(), unanswered={1, 2}), trials=2)
    trials = result.evidence["trials"]
    assert (trials["measured"], trials["success_rate"], trials["flaky"]) == (0, None, False)
    phase.vulnerabilities_found = ["vec"]  # the label shows on any listed finding
    phase.artifacts["vec"] = {"name": "Vector vec", "evidence": result.evidence}
    assert "Reproduced: no measured trials (2 unmeasured)" in _markdown(phase, result)


async def test_concurrency_above_one_warns_when_trials_run_serially() -> None:
    from structlog.testing import capture_logs

    with capture_logs() as logs:
        await _run(_Scripted(complies=set()), max_concurrent=3, trials=2)
    [warning] = [e for e in logs if e["event"] == "trials_run_serially"]
    assert (warning["trials"], warning["concurrency"]) == (2, 3)
