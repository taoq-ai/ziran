"""stop_on_critical stops only on a critical finding from exploitation_setup or later."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.strategies.adaptive import AdaptiveStrategy
from ziran.application.strategies.fixed import FixedStrategy
from ziran.domain.entities.phase import (
    CORE_PHASES,
    STOP_ON_CRITICAL_PHASES,
    PhaseResult,
    ScanPhase,
)

LATE = [
    ScanPhase.EXPLOITATION_SETUP,
    ScanPhase.EXECUTION,
    ScanPhase.PERSISTENCE,
    ScanPhase.EXFILTRATION,
]
EARLY = [p for p in ScanPhase if p not in LATE]


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    critical_in: ScanPhase,
    *,
    strategy: Any,
    phases: list[ScanPhase] | None = None,
    stop_on_critical: bool = True,
) -> list[ScanPhase]:
    async def fake_execute(self: Any, phase: ScanPhase, *a: Any, **k: Any) -> PhaseResult:
        found = ["crit" if phase == critical_in else "minor"]
        return PhaseResult(
            phase=phase,
            success=True,
            trust_score=0.5,
            vulnerabilities_found=found,
            duration_seconds=0.0,
        )

    monkeypatch.setattr(PhaseExecutor, "execute", fake_execute)
    library = AttackLibrary(load_builtin=False)
    monkeypatch.setattr(
        library,
        "get_vector",
        lambda i: SimpleNamespace(severity="critical" if i == "crit" else "low"),
    )
    scanner = AgentScanner(adapter=MockAgentAdapter(), attack_library=library)
    result = await scanner.run_campaign(
        phases=phases or list(ScanPhase),
        strategy=strategy,
        stop_on_critical=stop_on_critical,
    )
    return [p.phase for p in result.phases_executed]


def _strategies() -> list[Any]:
    return [
        lambda: FixedStrategy(stop_on_critical=True),
        lambda: AdaptiveStrategy(stop_on_critical=True),
    ]


@pytest.mark.unit
class TestStopOnCriticalPhases:
    def test_set_is_exploitation_setup_onwards(self) -> None:
        assert set(STOP_ON_CRITICAL_PHASES) == set(LATE)

    @pytest.mark.parametrize("make", _strategies())
    @pytest.mark.parametrize("phase", EARLY)
    async def test_early_critical_is_kept_and_campaign_continues(
        self, monkeypatch: pytest.MonkeyPatch, make: Any, phase: ScanPhase
    ) -> None:
        ran = await _run(monkeypatch, phase, strategy=make(), phases=list(CORE_PHASES))
        assert set(ran) == set(CORE_PHASES)

    @pytest.mark.parametrize("make", _strategies())
    @pytest.mark.parametrize("phase", LATE[:2])
    async def test_late_critical_stops_after_that_phase(
        self, monkeypatch: pytest.MonkeyPatch, make: Any, phase: ScanPhase
    ) -> None:
        ran = await _run(monkeypatch, phase, strategy=make(), phases=list(ScanPhase))
        assert phase in ran
        assert len(ran) < len(ScanPhase)
        assert ran.index(phase) == len(ran) - 1

    @pytest.mark.parametrize("make", _strategies())
    async def test_stop_on_critical_off_runs_every_phase(
        self, monkeypatch: pytest.MonkeyPatch, make: Any
    ) -> None:
        strategy = make()
        strategy._stop_on_critical = False
        ran = await _run(
            monkeypatch,
            ScanPhase.EXECUTION,
            strategy=strategy,
            phases=list(CORE_PHASES),
            stop_on_critical=False,
        )
        assert set(ran) == set(CORE_PHASES)

    async def test_default_is_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import inspect

        sig = inspect.signature(AgentScanner.run_campaign)
        assert sig.parameters["stop_on_critical"].default is True
