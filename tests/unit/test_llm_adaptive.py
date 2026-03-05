"""Unit tests for the LLM-powered adaptive campaign strategy."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.application.strategies.protocol import CampaignContext
from ziran.domain.entities.phase import PhaseResult, ScanPhase


def _mock_llm_client(response_content: str = "{}") -> MagicMock:
    client = MagicMock()
    resp = MagicMock()
    resp.content = response_content
    client.complete = AsyncMock(return_value=resp)
    return client


def _base_context(
    *,
    available: list[ScanPhase] | None = None,
    completed: list[PhaseResult] | None = None,
    capabilities: list[str] | None = None,
    total_vulns: int = 0,
    critical: bool = False,
) -> CampaignContext:
    return CampaignContext(
        available_phases=available or [ScanPhase.VULNERABILITY_DISCOVERY],
        completed_phases=completed or [],
        discovered_capabilities=capabilities or ["chat"],
        total_vulnerabilities=total_vulns,
        critical_found=critical,
    )


# ──────────────────────────────────────────────────────────────────────
# LLMAdaptiveStrategy.select_next_phase
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLLMSelectNextPhase:
    def test_llm_selects_phase(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        data = json.dumps(
            {
                "phase": "vulnerability_discovery",
                "reasoning": "test reason",
                "should_stop": False,
                "attack_boost_categories": ["injection"],
            }
        )
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(available=[ScanPhase.VULNERABILITY_DISCOVERY])

        decision = strategy.select_next_phase(ctx)

        assert decision is not None
        assert decision.phase == ScanPhase.VULNERABILITY_DISCOVERY
        assert "test reason" in decision.reasoning
        assert decision.attack_boost.get("injection") == 1.5

    def test_llm_recommends_stop(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        data = json.dumps(
            {
                "phase": "",
                "reasoning": "nothing more to test",
                "should_stop": True,
            }
        )
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context()

        decision = strategy.select_next_phase(ctx)
        assert decision is None

    def test_llm_invalid_phase_falls_back(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        data = json.dumps(
            {
                "phase": "nonexistent_phase",
                "reasoning": "oops",
                "should_stop": False,
            }
        )
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(available=[ScanPhase.RECONNAISSANCE])

        decision = strategy.select_next_phase(ctx)
        # Falls back to rule-based which picks from available
        assert decision is not None

    def test_llm_unavailable_phase_falls_back(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        data = json.dumps(
            {
                "phase": "execution",
                "reasoning": "jump ahead",
                "should_stop": False,
            }
        )
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(available=[ScanPhase.RECONNAISSANCE])

        decision = strategy.select_next_phase(ctx)
        assert decision is not None
        assert decision.phase == ScanPhase.RECONNAISSANCE

    def test_llm_exception_falls_back(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        llm = MagicMock()
        llm.complete = AsyncMock(side_effect=RuntimeError("LLM down"))
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(available=[ScanPhase.RECONNAISSANCE])

        decision = strategy.select_next_phase(ctx)
        assert decision is not None

    def test_no_available_phases_falls_back(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        llm = _mock_llm_client()
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(available=[])

        decision = strategy.select_next_phase(ctx)
        # Strategy falls back to scoring even with empty available phases
        assert decision is not None

    def test_with_completed_phases_context(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        phase_result = PhaseResult(
            phase=ScanPhase.RECONNAISSANCE,
            success=True,
            vulnerabilities_found=[],
            trust_score=0.5,
            duration_seconds=1.0,
        )
        data = json.dumps(
            {
                "phase": "vulnerability_discovery",
                "reasoning": "recon done",
                "should_stop": False,
            }
        )
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context(
            available=[ScanPhase.VULNERABILITY_DISCOVERY],
            completed=[phase_result],
        )

        decision = strategy.select_next_phase(ctx)
        assert decision is not None


# ──────────────────────────────────────────────────────────────────────
# LLMAdaptiveStrategy.prioritize_attacks
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLLMPrioritizeAttacks:
    def _make_attack(self, aid: str) -> Any:
        attack = MagicMock()
        attack.id = aid
        attack.name = f"Attack {aid}"
        attack.category = MagicMock(value="prompt_injection")
        attack.severity = "high"
        return attack

    def test_llm_reorders_attacks(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        attacks = [self._make_attack("a1"), self._make_attack("a2"), self._make_attack("a3")]
        data = json.dumps(["a3", "a1"])  # Reorder, skip a2
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        phase_result = PhaseResult(
            phase=ScanPhase.RECONNAISSANCE,
            success=True,
            vulnerabilities_found=[],
            trust_score=0.5,
            duration_seconds=1.0,
        )
        ctx = _base_context(completed=[phase_result])

        result = strategy.prioritize_attacks(attacks, ctx)
        assert [a.id for a in result] == ["a3", "a1", "a2"]

    def test_llm_prioritization_exception_falls_back(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        attacks = [self._make_attack("a1")]
        llm = MagicMock()
        llm.complete = AsyncMock(side_effect=RuntimeError("fail"))
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        ctx = _base_context()

        result = strategy.prioritize_attacks(attacks, ctx)
        assert len(result) == 1

    def test_llm_returns_dict_with_attack_ids(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        attacks = [self._make_attack("a1"), self._make_attack("a2")]
        data = json.dumps({"attack_ids": ["a2", "a1"]})
        llm = _mock_llm_client(data)
        strategy = LLMAdaptiveStrategy(llm_client=llm)
        phase_result = PhaseResult(
            phase=ScanPhase.RECONNAISSANCE,
            success=True,
            vulnerabilities_found=[],
            trust_score=0.5,
            duration_seconds=1.0,
        )
        ctx = _base_context(completed=[phase_result])

        result = strategy.prioritize_attacks(attacks, ctx)
        assert [a.id for a in result] == ["a2", "a1"]


# ──────────────────────────────────────────────────────────────────────
# LLMAdaptiveStrategy._parse_json_response
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestParseJsonResponse:
    def test_plain_json(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        result = LLMAdaptiveStrategy._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_fenced_json(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        result = LLMAdaptiveStrategy._parse_json_response('```json\n{"phase": "test"}\n```')
        assert result == {"phase": "test"}

    def test_json_array(self) -> None:
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        result = LLMAdaptiveStrategy._parse_json_response('["a", "b"]')
        assert result == ["a", "b"]
