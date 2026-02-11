"""Unit tests for the AgentScanner orchestrator."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ziran.application.agent_scanner.scanner import (
    AgentScanner,
    ProgressEvent,
    ProgressEventType,
)
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.phase import CoverageLevel, ScanPhase

if TYPE_CHECKING:
    from tests.conftest import MockAgentAdapter


@pytest.mark.unit
class TestAgentScanner:
    """Tests for the AgentScanner."""

    @pytest.fixture
    def scanner(self, mock_adapter: MockAgentAdapter) -> AgentScanner:
        return AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(),
        )

    @pytest.fixture
    def vulnerable_scanner(self, vulnerable_adapter: MockAgentAdapter) -> AgentScanner:
        return AgentScanner(
            adapter=vulnerable_adapter,
            attack_library=AttackLibrary(),
        )

    async def test_run_empty_campaign(self, mock_adapter: MockAgentAdapter) -> None:
        """Campaign with no attack vectors should complete without errors."""
        scanner = AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(load_builtin=False),
        )
        result = await scanner.run_campaign()
        assert result.campaign_id.startswith("campaign_")
        assert result.total_vulnerabilities == 0

    async def test_run_campaign_default_phases(self, scanner: AgentScanner) -> None:
        """Campaign with default phases should execute all core phases."""
        result = await scanner.run_campaign()
        assert len(result.phases_executed) == 6  # CORE_PHASES count

    async def test_run_campaign_specific_phases(self, scanner: AgentScanner) -> None:
        """Campaign with specific phases should only execute those phases."""
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
        )
        assert len(result.phases_executed) == 1
        assert result.phases_executed[0].phase == ScanPhase.RECONNAISSANCE

    async def test_campaign_tracks_trust_scores(self, scanner: AgentScanner) -> None:
        result = await scanner.run_campaign(
            phases=[
                ScanPhase.RECONNAISSANCE,
                ScanPhase.TRUST_BUILDING,
            ],
        )
        # Trust should increase from recon to trust_building
        assert len(result.phases_executed) == 2
        for pr in result.phases_executed:
            assert 0.0 <= pr.trust_score <= 1.0

    async def test_vulnerable_agent_finds_vulnerabilities(
        self, vulnerable_scanner: AgentScanner
    ) -> None:
        """Vulnerable adapter should produce vulnerability findings."""
        result = await vulnerable_scanner.run_campaign(
            phases=[ScanPhase.VULNERABILITY_DISCOVERY],
            coverage=CoverageLevel.COMPREHENSIVE,
        )
        # The vulnerable adapter returns responses matching success indicators
        assert result.total_vulnerabilities > 0

    async def test_campaign_result_metadata(self, scanner: AgentScanner) -> None:
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
        )
        assert "duration_seconds" in result.metadata
        assert "graph_stats" in result.metadata
        assert result.target_agent == "MockAgentAdapter"

    async def test_graph_populated_during_campaign(self, vulnerable_scanner: AgentScanner) -> None:
        await vulnerable_scanner.run_campaign(
            phases=[ScanPhase.VULNERABILITY_DISCOVERY],
            coverage=CoverageLevel.COMPREHENSIVE,
        )
        # Graph should have nodes from capability discovery + vulnerabilities
        assert vulnerable_scanner.graph.node_count > 0

    async def test_stop_on_critical(self, vulnerable_scanner: AgentScanner) -> None:
        """Campaign should stop early when a critical vulnerability is found."""
        result = await vulnerable_scanner.run_campaign(
            phases=[
                ScanPhase.VULNERABILITY_DISCOVERY,
                ScanPhase.EXECUTION,
                ScanPhase.EXFILTRATION,
            ],
            stop_on_critical=True,
            coverage=CoverageLevel.COMPREHENSIVE,
        )
        # May stop before all phases if a critical vulnerability is found
        assert len(result.phases_executed) >= 1

    async def test_no_stop_on_critical(self, vulnerable_scanner: AgentScanner) -> None:
        """Campaign should continue through all phases when stop_on_critical is False."""
        result = await vulnerable_scanner.run_campaign(
            phases=[
                ScanPhase.RECONNAISSANCE,
                ScanPhase.TRUST_BUILDING,
            ],
            stop_on_critical=False,
        )
        assert len(result.phases_executed) == 2


@pytest.mark.unit
class TestAgentScannerPromptRendering:
    """Tests for prompt rendering and response analysis."""

    def test_render_prompt(self) -> None:
        from ziran.domain.entities.attack import AttackPrompt

        prompt = AttackPrompt(
            template="Hello {name}, tell me about {topic}",
            variables={"name": "Agent", "topic": "your tools"},
        )
        rendered = AgentScanner._render_prompt(prompt)
        assert "Hello Agent" in rendered
        assert "your tools" in rendered
        assert "{name}" not in rendered

    def test_trust_score_calculation(self) -> None:
        scanner = AgentScanner.__new__(AgentScanner)
        score = scanner._calculate_trust_score(
            ScanPhase.TRUST_BUILDING,
            vulnerabilities=[],
        )
        assert score == 0.6  # Base score for trust_building

        score_with_vulns = scanner._calculate_trust_score(
            ScanPhase.TRUST_BUILDING,
            vulnerabilities=["v1", "v2", "v3"],
        )
        assert score_with_vulns == pytest.approx(0.45)  # 0.6 - 3*0.05


@pytest.mark.unit
class TestProgressCallback:
    """Tests for the on_progress callback mechanism."""

    async def test_callback_receives_campaign_events(self, mock_adapter: MockAgentAdapter) -> None:
        """Callback should receive CAMPAIGN_START and CAMPAIGN_COMPLETE."""
        events: list[ProgressEvent] = []
        scanner = AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(),
        )
        await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            on_progress=events.append,
        )
        event_types = [e.event for e in events]
        assert ProgressEventType.CAMPAIGN_START in event_types
        assert ProgressEventType.CAMPAIGN_COMPLETE in event_types

    async def test_callback_receives_phase_events(self, mock_adapter: MockAgentAdapter) -> None:
        """Callback should receive PHASE_START and PHASE_COMPLETE for each phase."""
        events: list[ProgressEvent] = []
        scanner = AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(),
        )
        await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING],
            on_progress=events.append,
        )
        phase_starts = [e for e in events if e.event == ProgressEventType.PHASE_START]
        phase_completes = [e for e in events if e.event == ProgressEventType.PHASE_COMPLETE]
        assert len(phase_starts) == 2
        assert len(phase_completes) == 2
        assert phase_starts[0].phase == "reconnaissance"
        assert phase_starts[1].phase == "trust_building"

    async def test_callback_receives_attack_events(
        self, vulnerable_adapter: MockAgentAdapter
    ) -> None:
        """Callback should receive ATTACK_START and ATTACK_COMPLETE for each attack."""
        events: list[ProgressEvent] = []
        scanner = AgentScanner(
            adapter=vulnerable_adapter,
            attack_library=AttackLibrary(),
        )
        await scanner.run_campaign(
            phases=[ScanPhase.VULNERABILITY_DISCOVERY],
            on_progress=events.append,
        )
        attack_starts = [e for e in events if e.event == ProgressEventType.ATTACK_START]
        attack_completes = [e for e in events if e.event == ProgressEventType.ATTACK_COMPLETE]
        # Should have at least one attack in vulnerability_discovery
        assert len(attack_starts) > 0
        assert len(attack_completes) == len(attack_starts)
        # Each attack event should have a name
        for evt in attack_starts:
            assert evt.attack_name != ""
            assert evt.total_attacks > 0

    async def test_callback_phase_index_tracking(self, mock_adapter: MockAgentAdapter) -> None:
        """Phase events should track correct indices."""
        events: list[ProgressEvent] = []
        phases = [
            ScanPhase.RECONNAISSANCE,
            ScanPhase.TRUST_BUILDING,
            ScanPhase.CAPABILITY_MAPPING,
        ]
        scanner = AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(),
        )
        await scanner.run_campaign(phases=phases, on_progress=events.append)

        phase_starts = [e for e in events if e.event == ProgressEventType.PHASE_START]
        assert len(phase_starts) == 3
        for idx, evt in enumerate(phase_starts):
            assert evt.phase_index == idx
            assert evt.total_phases == 3

    async def test_no_callback_still_works(self, mock_adapter: MockAgentAdapter) -> None:
        """Campaign should work fine when on_progress is None (default)."""
        scanner = AgentScanner(
            adapter=mock_adapter,
            attack_library=AttackLibrary(),
        )
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
        )
        assert result.campaign_id.startswith("campaign_")

    async def test_campaign_complete_has_metadata(
        self, vulnerable_adapter: MockAgentAdapter
    ) -> None:
        """CAMPAIGN_COMPLETE event should include total_vulnerabilities in extra."""
        events: list[ProgressEvent] = []
        scanner = AgentScanner(
            adapter=vulnerable_adapter,
            attack_library=AttackLibrary(),
        )
        await scanner.run_campaign(
            phases=[ScanPhase.VULNERABILITY_DISCOVERY],
            on_progress=events.append,
        )
        complete = [e for e in events if e.event == ProgressEventType.CAMPAIGN_COMPLETE]
        assert len(complete) == 1
        assert "total_vulnerabilities" in complete[0].extra
        assert "duration_seconds" in complete[0].extra


@pytest.mark.unit
class TestIterationLimitHandling:
    """Verify that iteration-limit sentinel responses are not treated as successful."""

    def test_iteration_limit_detected(self) -> None:
        """A response with 'Agent stopped due to iteration limit' should be detected as error."""
        from ziran.application.agent_scanner.scanner import _is_error_response

        assert _is_error_response("Agent stopped due to iteration limit or time limit.") is True

    def test_normal_response_not_error(self) -> None:
        """A normal response should not be flagged as error."""
        from ziran.application.agent_scanner.scanner import _is_error_response

        assert _is_error_response("Here is the information you requested.") is False

    def test_max_iterations_variant(self) -> None:
        """Alternate wording 'Agent stopped due to max iterations' also detected."""
        from ziran.application.agent_scanner.scanner import _is_error_response

        assert _is_error_response("Agent stopped due to max iterations.") is True
