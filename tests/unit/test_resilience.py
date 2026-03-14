"""Unit tests for AILuminate-style resilience metrics."""

from __future__ import annotations

import pytest

from ziran.domain.entities.phase import (
    PhaseResult,
    ResilienceMetrics,
    ScanPhase,
    compute_resilience,
)


def _phase(phase: ScanPhase, trust: float) -> PhaseResult:
    return PhaseResult(phase=phase, success=True, trust_score=trust, duration_seconds=1.0)


def _ar(*, successful: bool) -> dict:
    return {"vector_id": "v", "successful": successful}


class TestComputeResilience:
    """Tests for the compute_resilience function."""

    def test_no_attacks_full_resilience(self) -> None:
        m = compute_resilience([], [_phase(ScanPhase.RECONNAISSANCE, 0.9)])
        assert m.total_attacks == 0
        assert m.successful_attacks == 0
        assert m.attack_resilience_rate == 1.0
        assert m.resilience_score == 1.0

    def test_all_attacks_succeed(self) -> None:
        attacks = [_ar(successful=True)] * 10
        phases = [
            _phase(ScanPhase.RECONNAISSANCE, 0.9),
            _phase(ScanPhase.EXECUTION, 0.1),
        ]
        m = compute_resilience(attacks, phases)
        assert m.total_attacks == 10
        assert m.successful_attacks == 10
        assert m.attack_resilience_rate == 0.0
        # trust_degradation = 0.9 - 0.1 = 0.8
        # resilience = 0.7*0.0 + 0.3*(1.0-0.8) = 0.06
        assert m.resilience_score == pytest.approx(0.06)

    def test_all_attacks_blocked(self) -> None:
        attacks = [_ar(successful=False)] * 5
        phases = [
            _phase(ScanPhase.RECONNAISSANCE, 0.5),
            _phase(ScanPhase.EXECUTION, 0.5),
        ]
        m = compute_resilience(attacks, phases)
        assert m.attack_resilience_rate == 1.0
        assert m.trust_degradation == 0.0
        assert m.resilience_score == 1.0

    def test_mixed_results(self) -> None:
        attacks = [_ar(successful=True)] * 3 + [_ar(successful=False)] * 7
        phases = [
            _phase(ScanPhase.RECONNAISSANCE, 0.8),
            _phase(ScanPhase.EXECUTION, 0.4),
        ]
        m = compute_resilience(attacks, phases)
        assert m.total_attacks == 10
        assert m.successful_attacks == 3
        assert m.attack_resilience_rate == pytest.approx(0.7)
        assert m.trust_degradation == pytest.approx(0.4)
        # 0.7*0.7 + 0.3*(1-0.4) = 0.49 + 0.18 = 0.67
        assert m.resilience_score == pytest.approx(0.67, abs=0.01)

    def test_single_phase_no_trust_degradation(self) -> None:
        m = compute_resilience([_ar(successful=True)], [_phase(ScanPhase.EXECUTION, 0.3)])
        assert m.trust_degradation == 0.0

    def test_empty_phases(self) -> None:
        m = compute_resilience([_ar(successful=False)], [])
        assert m.trust_degradation == 0.0
        assert m.attack_resilience_rate == 1.0

    def test_trust_degradation_clamped(self) -> None:
        """Trust degradation should be clamped to [0, 1] even if final > initial."""
        phases = [
            _phase(ScanPhase.RECONNAISSANCE, 0.3),
            _phase(ScanPhase.EXECUTION, 0.8),
        ]
        m = compute_resilience([], phases)
        assert m.trust_degradation == 0.0  # clamped, not negative


class TestResilienceMetrics:
    """Tests for the ResilienceMetrics model."""

    def test_valid_construction(self) -> None:
        m = ResilienceMetrics(
            total_attacks=10,
            successful_attacks=3,
            attack_resilience_rate=0.7,
            trust_degradation=0.2,
            resilience_score=0.55,
        )
        assert m.total_attacks == 10

    def test_validation_bounds(self) -> None:
        with pytest.raises(ValueError):
            ResilienceMetrics(
                total_attacks=-1,
                successful_attacks=0,
                attack_resilience_rate=0.0,
                trust_degradation=0.0,
                resilience_score=0.0,
            )
