"""PAIR wiring (spec 081, PR 2): tactic dispatch, scanner arguments and the scan-cache skip."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from tests.unit.test_pair_executor import (
    BASE,
    GOAL,
    SECRET,
    WIN,
    Attacker,
    ScriptedJudge,
    ToyGuardAgent,
)
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache, is_cacheable
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.attacks.tactics import TacticType
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import AttackCategory, AttackPrompt, AttackResult, AttackVector
from ziran.domain.entities.phase import CoverageLevel, ScanPhase

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

PHASE = ScanPhase.EXPLOITATION_SETUP


def pair_vector(**pair: Any) -> AttackVector:
    return AttackVector(
        id="pair_wired",
        name="PAIR wired",
        category=AttackCategory.DATA_EXFILTRATION,
        target_phase=PHASE,
        description=GOAL,
        severity="high",
        tactic="pair",
        prompts=[AttackPrompt(template=BASE, success_indicators=[SECRET])],
        pair=pair or None,
    )


def pipeline() -> DetectorPipeline:
    return DetectorPipeline(llm_client=ScriptedJudge(), quality_scoring=True)


def library(tmp_path: Path, **pair: Any) -> AttackLibrary:
    import yaml

    data = pair_vector(**pair).model_dump(mode="json", exclude_none=True)
    (tmp_path / "pair.yaml").write_text(yaml.safe_dump({"vectors": [data]}))
    return AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)


def test_tactic_type_has_pair() -> None:
    assert TacticType("pair") is TacticType.PAIR


async def test_attack_executor_sends_pair_to_pair_executor() -> None:
    target, ledger = ToyGuardAgent(), UsageLedger()
    executor = AttackExecutor(
        target,
        pipeline(),
        attacker=Attacker(replies=[(BASE,), (WIN,)]),
        budget=CampaignBudget(ledger, UsageBudget()),
    )
    result = await executor.execute(pair_vector())
    assert result.successful
    assert result.evidence["pair"]["stop"] == "success"
    assert target.prompts == [BASE, WIN]  # the attacker's prompts, not the vector's turns
    assert [e.stage for e in ledger.entries()] == ["attacker"]


async def test_pair_without_attacker_is_an_error_not_multi_turn() -> None:
    target = ToyGuardAgent()
    result = await AttackExecutor(target, pipeline()).execute(pair_vector())
    assert not result.successful
    assert "attacker" in (result.error or "")
    assert target.prompts == []


async def test_attack_executor_passes_the_deadline_through() -> None:
    executor = AttackExecutor(ToyGuardAgent(), pipeline(), attacker=Attacker())
    deadline = asyncio.get_running_loop().time() - 1
    result = await executor.execute(pair_vector(), deadline=deadline)
    assert result.evidence["pair"]["stop"] == "timeout"


@pytest.mark.parametrize("site", ["run_campaign", "_execute_phase", "_execute_attack"])
async def test_scanner_passes_attacker_and_budget(site: str, tmp_path: Path) -> None:
    attacker = Attacker(replies=[(WIN,)])
    config = {"attacker_llm_client": attacker, "llm_client": ScriptedJudge()}
    scanner = AgentScanner(ToyGuardAgent(), attack_library=library(tmp_path), config=config)
    if site == "run_campaign":
        await scanner.run_campaign(phases=[PHASE], coverage=CoverageLevel.COMPREHENSIVE)
        result = scanner._attack_results[0]
    elif site == "_execute_phase":
        scanner._coverage = CoverageLevel.COMPREHENSIVE
        await scanner._execute_phase(PHASE)
        result = scanner._attack_results[0]
    else:
        result = await scanner._execute_attack(pair_vector())
    assert result.successful
    assert result.evidence["pair"]["attacker_model"] == "scripted-attacker"
    assert attacker.requests  # the same client object, unwrapped
    assert "attacker" in {e.stage for e in scanner._budget.ledger.entries()}


def test_pair_results_are_never_cacheable() -> None:
    def result(successful: bool) -> AttackResult:
        return AttackResult(
            vector_id="v",
            vector_name="v",
            category=AttackCategory.DATA_EXFILTRATION,
            severity="high",
            successful=successful,
            agent_response="reply",
            evidence={"pair": {"stop": "success" if successful else "max_iterations"}},
        )

    assert not is_cacheable(result(True))
    assert not is_cacheable(result(False))


async def test_scan_cache_writes_no_entry_for_a_failed_pair_vector(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    cache = ScanCache(CacheContext(ziran_version="0", target_sha256="0" * 64), root=cache_root)
    config = {"attacker_llm_client": Attacker(), "llm_client": ScriptedJudge(), "scan_cache": cache}
    scanner = AgentScanner(
        ToyGuardAgent(leak=False),
        attack_library=library(tmp_path, max_iterations=2),
        config=config,
    )
    await scanner.run_campaign(phases=[PHASE], coverage=CoverageLevel.COMPREHENSIVE)
    result = scanner._attack_results[0]
    assert not result.successful
    assert result.agent_response is not None  # cacheable but for the PAIR rule
    assert cache.stats.executed == 1
    assert list(cache_root.rglob("*.json")) == []


def test_not_run_line_once_per_vector_set() -> None:
    from ziran.application.attacks.pair import runnable

    warnings: list[str] = []
    static = pair_vector().model_copy(update={"id": "static", "tactic": "single"})
    assert runnable([static, pair_vector()], None, warnings) == [static]
    runnable([pair_vector()], None, warnings)  # the same phase again (a resume): no new line
    other = pair_vector().model_copy(update={"id": "pair_other"})
    runnable([other], None, warnings)  # another phase: its own line
    assert len(warnings) == 2
    assert "pair_wired" in warnings[0] and "pair_other" in warnings[1]
    assert runnable([pair_vector()], object(), warnings) == [pair_vector()]
    assert len(warnings) == 2
