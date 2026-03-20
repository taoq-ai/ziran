"""Unit tests for CLI helper functions — display & strategy helpers.

Tests for display functions in ``ziran.interfaces.cli.main`` that do
not require Click runner setup: ``_display_session_results``,
``_display_gate_result``, ``_display_audit_report``,
``_display_policy_verdict``, ``_load_pentest_adapter``.

Factory functions (``build_strategy``, ``load_agent_adapter``,
``load_remote_adapter``) have been extracted to
``ziran.application.factories`` — see ``test_factories.py``.
"""

from __future__ import annotations

import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────
# _build_strategy
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBuildStrategy:
    """Tests for build_strategy (extracted to ziran.application.factories)."""

    def test_fixed_strategy(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("fixed", stop_on_critical=True)
        assert strategy.__class__.__name__ == "FixedStrategy"

    def test_adaptive_strategy(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("adaptive", stop_on_critical=False)
        assert strategy.__class__.__name__ == "AdaptiveStrategy"

    def test_llm_adaptive_with_client(self) -> None:
        from ziran.application.factories import build_strategy

        mock_llm = MagicMock()
        strategy = build_strategy("llm-adaptive", stop_on_critical=True, llm_client=mock_llm)
        assert strategy.__class__.__name__ == "LLMAdaptiveStrategy"

    def test_llm_adaptive_without_client_falls_back(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("llm-adaptive", stop_on_critical=False, llm_client=None)
        # Falls back to AdaptiveStrategy when no LLM client
        assert strategy.__class__.__name__ == "AdaptiveStrategy"

    def test_unknown_strategy_defaults_to_fixed(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("unknown", stop_on_critical=True)
        assert strategy.__class__.__name__ == "FixedStrategy"


# ──────────────────────────────────────────────────────────────────────
# _display_session_results
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDisplaySessionResults:
    """Tests for _display_session_results."""

    def test_non_session_returns_early(self) -> None:
        from ziran.interfaces.cli.main import _display_session_results

        # Should not crash with non-PentestSession input
        _display_session_results("not a session")

    def test_renders_session_with_steps(self) -> None:
        from ziran.domain.entities.pentest import (
            PentestSession,
            PentestStatus,
            PentestStep,
            PentestStepType,
        )
        from ziran.interfaces.cli.main import _display_session_results

        session = PentestSession(max_iterations=5)
        session.status = PentestStatus.COMPLETE
        session.total_vulnerabilities = 3
        session.total_attacks_executed = 10
        session.iteration_count = 2
        session.add_step(
            PentestStep(
                step_type=PentestStepType.SCAN,
                reasoning="test",
                result_summary="Found 3 vulns",
                duration_seconds=1.5,
            )
        )

        # Should not raise
        _display_session_results(session)

    def test_renders_session_with_findings(self) -> None:
        from ziran.domain.entities.pentest import (
            DeduplicatedFinding,
            PentestSession,
            PentestStatus,
            PentestStep,
            PentestStepType,
        )
        from ziran.interfaces.cli.main import _display_session_results

        session = PentestSession(max_iterations=5)
        session.status = PentestStatus.COMPLETE
        session.total_vulnerabilities = 2
        session.iteration_count = 1
        session.add_step(
            PentestStep(
                step_type=PentestStepType.SCAN,
                reasoning="test",
                result_summary="Scan done",
                duration_seconds=1.0,
            )
        )
        session.findings = [
            DeduplicatedFinding(
                canonical_title="Prompt Injection",
                canonical_description="desc",
                severity="high",
                owasp_categories=["LLM01"],
                attack_result_ids=["v1"],
            ),
        ]

        _display_session_results(session)

    def test_renders_session_no_steps_no_findings(self) -> None:
        from ziran.domain.entities.pentest import PentestSession, PentestStatus
        from ziran.interfaces.cli.main import _display_session_results

        session = PentestSession(max_iterations=5)
        session.status = PentestStatus.COMPLETE
        _display_session_results(session)


# ──────────────────────────────────────────────────────────────────────
# _display_gate_result
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDisplayGateResult:
    """Tests for _display_gate_result."""

    def test_gate_passed_no_violations(self) -> None:
        from ziran.domain.entities.ci import FindingCount, GateResult, GateStatus
        from ziran.interfaces.cli.main import _display_gate_result

        gate = GateResult(
            status=GateStatus.PASSED,
            trust_score=0.95,
            finding_counts=FindingCount(),
            violations=[],
            summary="All checks passed",
        )
        _display_gate_result(gate)

    def test_gate_failed_with_violations(self) -> None:
        from ziran.domain.entities.ci import (
            FindingCount,
            GateResult,
            GateStatus,
            GateViolation,
        )
        from ziran.interfaces.cli.main import _display_gate_result

        gate = GateResult(
            status=GateStatus.FAILED,
            trust_score=0.3,
            finding_counts=FindingCount(critical=2, high=3),
            violations=[
                GateViolation(
                    rule="max_critical",
                    message="Too many critical findings",
                    severity="critical",
                ),
                GateViolation(
                    rule="min_trust",
                    message="Trust score below threshold",
                    severity="high",
                ),
            ],
            summary="Gate failed: critical findings detected",
        )
        _display_gate_result(gate)


# ──────────────────────────────────────────────────────────────────────
# _display_audit_report
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDisplayAuditReport:
    """Tests for _display_audit_report."""

    def test_no_findings(self) -> None:
        from ziran.interfaces.cli.main import _display_audit_report

        report = MagicMock()
        report.findings = []
        report.files_analyzed = 3

        _display_audit_report(report)

    def test_with_findings_and_recommendations(self) -> None:
        from ziran.interfaces.cli.main import _display_audit_report

        finding1 = MagicMock()
        finding1.check_id = "ZIRAN-01"
        finding1.severity = "critical"
        finding1.message = "Dangerous tool exposed"
        finding1.file_path = "agent.py"
        finding1.line_number = 42
        finding1.recommendation = "Remove the tool"

        finding2 = MagicMock()
        finding2.check_id = "ZIRAN-05"
        finding2.severity = "high"
        finding2.message = "No guardrails"
        finding2.file_path = "config.py"
        finding2.line_number = None
        finding2.recommendation = "Add guardrails"

        report = MagicMock()
        report.findings = [finding1, finding2]
        report.total_issues = 2
        report.files_analyzed = 5
        report.critical_count = 1
        report.high_count = 1
        report.passed = True  # passed=True so no sys.exit

        _display_audit_report(report)

    def test_failed_report_exits(self) -> None:
        from ziran.interfaces.cli.main import _display_audit_report

        finding1 = MagicMock()
        finding1.check_id = "ZIRAN-01"
        finding1.severity = "critical"
        finding1.message = "Bad"
        finding1.file_path = "x.py"
        finding1.line_number = 1
        finding1.recommendation = None

        report = MagicMock()
        report.findings = [finding1]
        report.total_issues = 1
        report.files_analyzed = 1
        report.critical_count = 1
        report.high_count = 0
        report.passed = False

        with pytest.raises(SystemExit):
            _display_audit_report(report)


# ──────────────────────────────────────────────────────────────────────
# _display_policy_verdict
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDisplayPolicyVerdict:
    """Tests for _display_policy_verdict."""

    def test_verdict_all_clear(self) -> None:
        from ziran.domain.entities.policy import PolicyVerdict
        from ziran.interfaces.cli.main import _display_policy_verdict

        verdict = PolicyVerdict(
            policy_id="p1",
            policy_name="Test Policy",
            passed=True,
            violations=[],
            warnings=[],
            info=[],
            summary="All clear",
        )
        _display_policy_verdict(verdict)

    def test_verdict_with_violations_and_warnings(self) -> None:
        from ziran.domain.entities.policy import PolicyVerdict, PolicyViolation, RuleType
        from ziran.interfaces.cli.main import _display_policy_verdict

        verdict = PolicyVerdict(
            policy_id="p1",
            policy_name="Test Policy",
            passed=True,  # passed=True so no sys.exit
            violations=[
                PolicyViolation(
                    rule_type=RuleType.MAX_CRITICAL_VULNS,
                    message="Too many criticals",
                ),
            ],
            warnings=[
                PolicyViolation(
                    rule_type=RuleType.MIN_TRUST_SCORE,
                    message="Trust low",
                    severity="warning",
                ),
            ],
            info=[
                PolicyViolation(
                    rule_type=RuleType.MAX_HIGH_VULNS,
                    message="FYI",
                    severity="info",
                ),
            ],
            summary="Some issues",
        )
        _display_policy_verdict(verdict)

    def test_verdict_failed_exits(self) -> None:
        from ziran.domain.entities.policy import PolicyVerdict, PolicyViolation, RuleType
        from ziran.interfaces.cli.main import _display_policy_verdict

        verdict = PolicyVerdict(
            policy_id="p1",
            policy_name="Test Policy",
            passed=False,
            violations=[
                PolicyViolation(
                    rule_type=RuleType.MAX_CRITICAL_VULNS,
                    message="Critical exceeded",
                ),
            ],
            summary="Failed",
        )

        with pytest.raises(SystemExit):
            _display_policy_verdict(verdict)


# ──────────────────────────────────────────────────────────────────────
# _load_pentest_adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadPentestAdapter:
    """Tests for _load_pentest_adapter."""

    def test_target_yaml(self) -> None:
        from ziran.interfaces.cli.main import _load_pentest_adapter

        yaml_content = "url: https://agent.example.com\nprotocol: rest\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()

            adapter = _load_pentest_adapter(framework=None, target=f.name)
            assert adapter is not None
            assert adapter.__class__.__name__ == "HttpAgentAdapter"

    def test_framework_without_target_exits(self) -> None:
        from ziran.interfaces.cli.main import _load_pentest_adapter

        with pytest.raises(SystemExit):
            _load_pentest_adapter(framework="langchain", target=None)

    def test_neither_framework_nor_target_exits(self) -> None:
        from ziran.interfaces.cli.main import _load_pentest_adapter

        with pytest.raises(SystemExit):
            _load_pentest_adapter(framework=None, target=None)


# ──────────────────────────────────────────────────────────────────────
# _load_agent_adapter branches
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadAgentAdapter:
    """Tests for load_agent_adapter (extracted to ziran.application.factories)."""

    def test_langchain_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("langchain", "/fake/path.py")
            assert adapter.__class__.__name__ == "LangChainAdapter"

    def test_crewai_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("crewai", "/fake/path.py")
            assert adapter.__class__.__name__ == "CrewAIAdapter"

    def test_bedrock_import_error(self) -> None:
        """Test bedrock path when boto3 is not installed."""
        from ziran.application.factories import load_agent_adapter

        with (
            patch("ziran.application.factories._load_bedrock_config") as mock_cfg,
            patch.dict(sys.modules, {"boto3": None}),
        ):
            mock_cfg.return_value = {"agent_id": "test123", "region_name": "us-east-1"}
            # BedrockAdapter will fail on boto3 import
            try:
                adapter = load_agent_adapter("bedrock", "/fake/config.yaml")
                # If boto3 happens to be installed, just check type
                assert adapter.__class__.__name__ == "BedrockAdapter"
            except ImportError:
                pass  # Expected when boto3 is missing

    def test_agentcore_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("agentcore", "/fake/path.py")
            assert adapter.__class__.__name__ == "AgentCoreAdapter"

    def test_unsupported_framework_raises(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with pytest.raises(ValueError, match="Unsupported"):
            load_agent_adapter("unknown_fw", "/fake/path.py")


# ──────────────────────────────────────────────────────────────────────
# _load_remote_adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadRemoteAdapter:
    """Tests for load_remote_adapter (extracted to ziran.application.factories)."""

    def test_loads_from_yaml(self) -> None:
        from ziran.application.factories import load_remote_adapter

        yaml_content = "url: https://api.example.com\nprotocol: openai\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()

            adapter, _config = load_remote_adapter(f.name)
            assert adapter is not None
            assert adapter.__class__.__name__ == "HttpAgentAdapter"


# ──────────────────────────────────────────────────────────────────────
# _display_results token usage branch
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDisplayResultsTokenBranch:
    """Cover token_usage display branch in _display_results."""

    def test_display_with_token_usage(self) -> None:
        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli.main import _display_results

        result = CampaignResult(
            campaign_id="test-campaign",
            target_agent="test-agent",
            phases_executed=[],
            total_vulnerabilities=3,
            final_trust_score=0.4,
            success=True,
            attack_results=[],
            token_usage={
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
            },
        )

        # Should not raise
        _display_results(result)
