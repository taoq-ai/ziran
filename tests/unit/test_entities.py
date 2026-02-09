"""Unit tests for domain entity models."""

from __future__ import annotations

import pytest

from koan.domain.entities.attack import (
    AttackCategory,
    AttackPrompt,
    AttackResult,
    AttackVector,
)
from koan.domain.entities.capability import (
    AgentCapability,
    CapabilityType,
    ToolChain,
)
from koan.domain.entities.phase import (
    CORE_PHASES,
    PHASE_ORDER,
    CampaignResult,
    PhaseResult,
    RomanceScanPhase,
)

# ──────────────────────────────────────────────────────────────────────
# RomanceScanPhase
# ──────────────────────────────────────────────────────────────────────


class TestRomanceScanPhase:
    """Tests for the RomanceScanPhase enum."""

    def test_phase_values(self) -> None:
        assert RomanceScanPhase.RECONNAISSANCE == "reconnaissance"
        assert RomanceScanPhase.TRUST_BUILDING == "trust_building"
        assert RomanceScanPhase.EXECUTION == "execution"

    def test_all_phases_in_order(self) -> None:
        assert len(PHASE_ORDER) == 8

    def test_core_phases_subset_of_all(self) -> None:
        for phase in CORE_PHASES:
            assert phase in PHASE_ORDER

    def test_core_phases_count(self) -> None:
        assert len(CORE_PHASES) == 6

    def test_phase_from_string(self) -> None:
        phase = RomanceScanPhase("reconnaissance")
        assert phase == RomanceScanPhase.RECONNAISSANCE

    def test_invalid_phase_raises(self) -> None:
        with pytest.raises(ValueError):
            RomanceScanPhase("nonexistent_phase")


# ──────────────────────────────────────────────────────────────────────
# PhaseResult
# ──────────────────────────────────────────────────────────────────────


class TestPhaseResult:
    """Tests for PhaseResult model."""

    def test_valid_phase_result(self) -> None:
        result = PhaseResult(
            phase=RomanceScanPhase.RECONNAISSANCE,
            success=True,
            trust_score=0.5,
            duration_seconds=1.5,
        )
        assert result.phase == RomanceScanPhase.RECONNAISSANCE
        assert result.success is True
        assert result.trust_score == 0.5
        assert result.vulnerabilities_found == []

    def test_trust_score_validation(self) -> None:
        with pytest.raises(ValueError):
            PhaseResult(
                phase=RomanceScanPhase.RECONNAISSANCE,
                success=False,
                trust_score=1.5,  # > 1.0
                duration_seconds=0.0,
            )

    def test_trust_score_lower_bound(self) -> None:
        with pytest.raises(ValueError):
            PhaseResult(
                phase=RomanceScanPhase.RECONNAISSANCE,
                success=False,
                trust_score=-0.1,
                duration_seconds=0.0,
            )

    def test_phase_result_with_vulnerabilities(self) -> None:
        result = PhaseResult(
            phase=RomanceScanPhase.VULNERABILITY_DISCOVERY,
            success=True,
            trust_score=0.4,
            vulnerabilities_found=["vuln_1", "vuln_2"],
            duration_seconds=5.0,
        )
        assert len(result.vulnerabilities_found) == 2

    def test_phase_result_with_error(self) -> None:
        result = PhaseResult(
            phase=RomanceScanPhase.EXECUTION,
            success=False,
            trust_score=0.2,
            duration_seconds=0.1,
            error="Connection timeout",
        )
        assert result.error == "Connection timeout"


# ──────────────────────────────────────────────────────────────────────
# CampaignResult
# ──────────────────────────────────────────────────────────────────────


class TestCampaignResult:
    """Tests for CampaignResult model."""

    def test_campaign_result_creation(self) -> None:
        result = CampaignResult(
            campaign_id="test_001",
            target_agent="MockAgent",
            phases_executed=[],
            total_vulnerabilities=0,
            final_trust_score=0.0,
            success=False,
        )
        assert result.campaign_id == "test_001"
        assert result.all_vulnerabilities == []

    def test_campaign_result_with_phases(self) -> None:
        phase1 = PhaseResult(
            phase=RomanceScanPhase.RECONNAISSANCE,
            success=True,
            trust_score=0.3,
            vulnerabilities_found=["vuln_a"],
            discovered_capabilities=["cap_1"],
            duration_seconds=1.0,
        )
        phase2 = PhaseResult(
            phase=RomanceScanPhase.TRUST_BUILDING,
            success=False,
            trust_score=0.6,
            duration_seconds=2.0,
        )

        result = CampaignResult(
            campaign_id="test_002",
            target_agent="MockAgent",
            phases_executed=[phase1, phase2],
            total_vulnerabilities=1,
            final_trust_score=0.6,
            success=True,
        )

        assert result.all_vulnerabilities == ["vuln_a"]
        assert result.all_capabilities == ["cap_1"]
        assert len(result.phases_with_findings) == 1

    def test_campaign_result_critical_paths(self) -> None:
        result = CampaignResult(
            campaign_id="test_003",
            target_agent="MockAgent",
            phases_executed=[],
            total_vulnerabilities=3,
            critical_paths=[["tool_a", "tool_b", "data_c"]],
            final_trust_score=0.2,
            success=True,
        )
        assert len(result.critical_paths) == 1


# ──────────────────────────────────────────────────────────────────────
# AgentCapability
# ──────────────────────────────────────────────────────────────────────


class TestAgentCapability:
    """Tests for AgentCapability model."""

    def test_basic_capability(self) -> None:
        cap = AgentCapability(
            id="tool_search",
            name="search",
            type=CapabilityType.TOOL,
        )
        assert cap.is_tool is True
        assert cap.is_high_risk is False
        assert cap.dangerous is False

    def test_dangerous_capability(self) -> None:
        cap = AgentCapability(
            id="tool_shell",
            name="shell_execute",
            type=CapabilityType.TOOL,
            dangerous=True,
        )
        assert cap.is_high_risk is True

    def test_permission_gated_capability(self) -> None:
        cap = AgentCapability(
            id="tool_admin",
            name="admin_panel",
            type=CapabilityType.PERMISSION,
            requires_permission=True,
        )
        assert cap.is_tool is False
        assert cap.is_high_risk is True

    def test_capability_types(self) -> None:
        assert CapabilityType.TOOL == "tool"
        assert CapabilityType.SKILL == "skill"
        assert CapabilityType.DATA_ACCESS == "data_access"
        assert CapabilityType.EXTERNAL_API == "external_api"


# ──────────────────────────────────────────────────────────────────────
# ToolChain
# ──────────────────────────────────────────────────────────────────────


class TestToolChain:
    """Tests for ToolChain model."""

    def test_tool_chain(self) -> None:
        chain = ToolChain(
            tools=["search", "email", "shell"],
            risk_score=0.8,
            exploit_path=["node_a", "node_b", "node_c"],
            description="Search -> Email -> Shell chain",
        )
        assert chain.length == 3
        assert chain.risk_score == 0.8

    def test_tool_chain_risk_validation(self) -> None:
        with pytest.raises(ValueError):
            ToolChain(
                tools=["a"],
                risk_score=1.5,  # > 1.0
                exploit_path=["x"],
                description="Invalid",
            )


# ──────────────────────────────────────────────────────────────────────
# AttackVector
# ──────────────────────────────────────────────────────────────────────


class TestAttackVector:
    """Tests for AttackVector model."""

    def test_basic_attack_vector(self, sample_attack_vector: AttackVector) -> None:
        assert sample_attack_vector.id == "test_pi_basic"
        assert sample_attack_vector.category == AttackCategory.PROMPT_INJECTION
        assert sample_attack_vector.is_critical is False  # severity is "high"
        assert sample_attack_vector.prompt_count == 1

    def test_critical_attack_vector(self) -> None:
        vector = AttackVector(
            id="test_critical",
            name="Critical Test",
            category=AttackCategory.DATA_EXFILTRATION,
            target_phase=RomanceScanPhase.EXECUTION,
            description="Critical test",
            severity="critical",
        )
        assert vector.is_critical is True
        assert vector.prompt_count == 0

    def test_attack_categories(self) -> None:
        assert AttackCategory.PROMPT_INJECTION == "prompt_injection"
        assert AttackCategory.TOOL_MANIPULATION == "tool_manipulation"
        assert AttackCategory.MEMORY_POISONING == "memory_poisoning"

    def test_invalid_severity(self) -> None:
        with pytest.raises(ValueError):
            AttackVector(
                id="bad",
                name="Bad",
                category=AttackCategory.PROMPT_INJECTION,
                target_phase=RomanceScanPhase.EXECUTION,
                description="Bad",
                severity="extreme",  # not valid
            )


# ──────────────────────────────────────────────────────────────────────
# AttackResult
# ──────────────────────────────────────────────────────────────────────


class TestAttackResult:
    """Tests for AttackResult model."""

    def test_successful_result(self, sample_attack_result: AttackResult) -> None:
        assert sample_attack_result.successful is True
        assert sample_attack_result.vector_id == "test_pi_basic"

    def test_failed_result(self) -> None:
        result = AttackResult(
            vector_id="test_fail",
            vector_name="Failed Attack",
            category=AttackCategory.PROMPT_INJECTION,
            severity="low",
            successful=False,
            error="Attack was blocked",
        )
        assert result.successful is False
        assert result.error is not None


# ──────────────────────────────────────────────────────────────────────
# AttackPrompt
# ──────────────────────────────────────────────────────────────────────


class TestAttackPrompt:
    """Tests for AttackPrompt model."""

    def test_basic_prompt(self) -> None:
        prompt = AttackPrompt(
            template="Hello {name}",
            variables={"name": "World"},
            success_indicators=["success"],
            failure_indicators=["blocked"],
        )
        assert "{name}" in prompt.template
        assert len(prompt.success_indicators) == 1

    def test_prompt_defaults(self) -> None:
        prompt = AttackPrompt(template="Simple prompt")
        assert prompt.variables == {}
        assert prompt.success_indicators == []
        assert prompt.failure_indicators == []
