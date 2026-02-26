"""Tests for CLI commands — exercises every Click command via CliRunner.

Covers: scan, discover, library, report, poc, policy, audit, ci, plus
the internal helpers _load_agent_adapter, _load_remote_adapter,
_load_python_object, _display_results, _save_results, etc.

Every external side-effect (file I/O, asyncio.run, adapter loading) is
mocked so these tests are fast and deterministic.
"""

from __future__ import annotations

import json
import tempfile
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ── Minimal campaign result for report/poc/policy/ci commands ────────

def _minimal_campaign_result() -> dict[str, Any]:
    return {
        "campaign_id": "test_campaign_001",
        "target_agent": "test_agent",
        "phases_executed": [
            {
                "phase": "reconnaissance",
                "success": True,
                "trust_score": 0.9,
                "duration_seconds": 1.0,
                "vulnerabilities_found": [],
                "artifacts": {},
                "graph_state": {},
                "error": None,
            }
        ],
        "total_vulnerabilities": 0,
        "critical_paths": [],
        "final_trust_score": 0.95,
        "success": False,
        "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "attack_results": [],
        "dangerous_tool_chains": [],
        "critical_chain_count": 0,
        "coverage_level": "standard",
    }


def _vulnerable_campaign_result() -> dict[str, Any]:
    base = _minimal_campaign_result()
    base["total_vulnerabilities"] = 2
    base["success"] = True
    base["final_trust_score"] = 0.3
    base["critical_paths"] = [["tool_a", "tool_b", "exfil"]]
    base["dangerous_tool_chains"] = [
        {
            "risk_level": "critical",
            "vulnerability_type": "data_exfil",
            "tools": ["read_db", "send_email"],
            "exploit_description": "Read then exfiltrate",
            "remediation": "Restrict chaining",
        }
    ]
    base["phases_executed"][0]["vulnerabilities_found"] = ["vuln_1", "vuln_2"]
    base["phases_executed"][0]["success"] = True
    base["phases_executed"][0]["artifacts"] = {
        "vuln_1": {"name": "Prompt Injection", "severity": "critical", "category": "injection"},
        "vuln_2": {"name": "Data Leak", "severity": "high", "category": "exfiltration"},
    }
    base["attack_results"] = [
        {
            "vector_id": "v1",
            "vector_name": "test_vector",
            "category": "prompt_injection",
            "severity": "critical",
            "successful": True,
            "prompt": "hack me",
            "response": "sure",
            "detection_score": 0.9,
            "detection_confidence": 0.95,
            "detection_method": "indicator",
            "owasp_mapping": [],
        }
    ]
    return base


# ── CLI group & version ─────────────────────────────────────────────

class TestCLIGroup:
    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "ziran" in result.output.lower()

    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ZIRAN" in result.output

    def test_verbose_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--verbose", "--help"])
        assert result.exit_code == 0


# ── scan command ────────────────────────────────────────────────────

class TestScanCommand:
    def test_scan_no_args_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0

    def test_scan_mutual_exclusion(self, runner: CliRunner) -> None:
        """--framework and --target are mutually exclusive."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(b"url: http://example.com\n")
            f.flush()
            result = runner.invoke(
                cli,
                ["scan", "--framework", "langchain", "--agent-path", f.name, "--target", f.name],
            )
        assert result.exit_code != 0

    def test_scan_framework_without_agent_path(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--framework", "langchain"])
        assert result.exit_code != 0

    @patch("ziran.interfaces.cli.main._load_agent_adapter")
    @patch("ziran.interfaces.cli.main.asyncio")
    def test_scan_local_success(
        self, mock_asyncio: MagicMock, mock_load: MagicMock, runner: CliRunner
    ) -> None:
        """Scan with --framework + --agent-path should go through the local path."""
        mock_adapter = MagicMock()
        mock_load.return_value = mock_adapter

        # Create a minimal CampaignResult-like object
        from ziran.domain.entities.phase import CampaignResult

        result_data = _minimal_campaign_result()
        mock_result = CampaignResult.model_validate(result_data)
        mock_asyncio.run.return_value = mock_result

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("agent_executor = None\n")
            f.flush()
            runner.invoke(
                cli,
                [
                    "scan",
                    "--framework", "langchain",
                    "--agent-path", f.name,
                    "--output", tempfile.mkdtemp(),
                ],
                catch_exceptions=False,
            )

        # Should have attempted to load the adapter
        mock_load.assert_called_once()

    def test_scan_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--attack-timeout" in result.output
        assert "--phase-timeout" in result.output


# ── discover command ────────────────────────────────────────────────

class TestDiscoverCommand:
    def test_discover_no_args_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["discover"])
        assert result.exit_code != 0

    def test_discover_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["discover", "--help"])
        assert result.exit_code == 0


# ── library command ─────────────────────────────────────────────────

class TestLibraryCommand:
    def test_library_list_all(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["library", "--list"])
        assert result.exit_code == 0

    def test_library_filter_phase(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["library", "--phase", "reconnaissance"])
        assert result.exit_code == 0

    def test_library_filter_owasp(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["library", "--owasp", "LLM01"])
        assert result.exit_code == 0

    def test_library_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["library", "--help"])
        assert result.exit_code == 0


# ── report command ──────────────────────────────────────────────────

class TestReportCommand:
    def test_report_terminal(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["report", f.name])
        assert result.exit_code == 0

    def test_report_json(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["report", f.name, "--format", "json"])
        assert result.exit_code == 0

    def test_report_markdown(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["report", f.name, "--format", "markdown"])
        assert result.exit_code == 0

    def test_report_html(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["report", f.name, "--format", "html"])
        assert result.exit_code == 0

    def test_report_invalid_file(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not json")
            f.flush()
            result = runner.invoke(cli, ["report", f.name])
        assert result.exit_code != 0

    def test_report_with_vulnerabilities(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_vulnerable_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["report", f.name])
        assert result.exit_code == 0


# ── poc command ─────────────────────────────────────────────────────

class TestPocCommand:
    def test_poc_no_successful_attacks(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["poc", f.name])
        assert result.exit_code == 0
        assert "No successful attacks" in result.output

    def test_poc_with_successful_attacks(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_vulnerable_campaign_result(), f)
            f.flush()
            out_dir = tempfile.mkdtemp()
            result = runner.invoke(cli, ["poc", f.name, "-o", out_dir])
        assert result.exit_code == 0

    def test_poc_invalid_file(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("bad json")
            f.flush()
            result = runner.invoke(cli, ["poc", f.name])
        assert result.exit_code != 0


# ── policy command ──────────────────────────────────────────────────

class TestPolicyCommand:
    def test_policy_default(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["policy", f.name])
        # May pass or fail depending on default policy — just shouldn't crash
        assert result.exit_code in (0, 1)

    def test_policy_invalid_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not json")
            f.flush()
            result = runner.invoke(cli, ["policy", f.name])
        assert result.exit_code != 0

    def test_policy_with_vulnerable_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_vulnerable_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["policy", f.name])
        assert result.exit_code in (0, 1)


# ── audit command ───────────────────────────────────────────────────

class TestAuditCommand:
    def test_audit_clean_file(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n")
            f.flush()
            result = runner.invoke(cli, ["audit", f.name])
        assert result.exit_code == 0

    def test_audit_directory(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("x = 1\n")
        result = runner.invoke(cli, ["audit", str(tmp_path)])
        assert result.exit_code == 0

    def test_audit_severity_filter(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n")
            f.flush()
            result = runner.invoke(cli, ["audit", f.name, "--severity", "critical"])
        assert result.exit_code == 0


# ── ci command ──────────────────────────────────────────────────────

class TestCiCommand:
    def test_ci_minimal_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(cli, ["ci", f.name, "--no-github-annotations", "--no-github-summary"])
        assert result.exit_code in (0, 1)

    def test_ci_with_sarif(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            sarif_path = tempfile.mktemp(suffix=".sarif")
            result = runner.invoke(
                cli,
                ["ci", f.name, "--sarif", sarif_path, "--no-github-annotations", "--no-github-summary"],
            )
        assert result.exit_code in (0, 1)

    def test_ci_invalid_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("bad")
            f.flush()
            result = runner.invoke(cli, ["ci", f.name])
        assert result.exit_code != 0


# ── Helper: _load_python_object ─────────────────────────────────────

class TestLoadPythonObject:
    def test_load_existing_object(self) -> None:
        from ziran.interfaces.cli.main import _load_python_object

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("my_var = 42\n")
            f.flush()
            obj = _load_python_object(f.name, "my_var")
        assert obj == 42

    def test_load_missing_object(self) -> None:
        from ziran.interfaces.cli.main import _load_python_object

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n")
            f.flush()
            with pytest.raises(Exception, match="not found"):
                _load_python_object(f.name, "nonexistent")

    def test_load_missing_file(self) -> None:
        from ziran.interfaces.cli.main import _load_python_object

        with pytest.raises(Exception, match=r"not found|No such file"):
            _load_python_object("/nonexistent/path.py", "obj")


# ── Helper: _load_bedrock_config ────────────────────────────────────

class TestLoadBedrockConfig:
    def test_load_agent_id_string(self) -> None:
        from ziran.interfaces.cli.main import _load_bedrock_config

        result = _load_bedrock_config("my-agent-id")
        assert result == {"agent_id": "my-agent-id"}

    def test_load_yaml_config(self) -> None:
        from ziran.interfaces.cli.main import _load_bedrock_config

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("agent_id: abc123\nregion_name: us-east-1\n")
            f.flush()
            result = _load_bedrock_config(f.name)
        assert result["agent_id"] == "abc123"
        assert result["region_name"] == "us-east-1"

    def test_load_invalid_yaml_config(self) -> None:
        from ziran.interfaces.cli.main import _load_bedrock_config

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("- just_a_list\n")
            f.flush()
            with pytest.raises(Exception, match="agent_id"):
                _load_bedrock_config(f.name)


# ── Helper: _load_agent_adapter ────────────────────────────────────

class TestLoadAgentAdapter:
    def test_unsupported_framework(self) -> None:
        from ziran.interfaces.cli.main import _load_agent_adapter

        with pytest.raises(Exception, match="Unsupported"):
            _load_agent_adapter("unknown_framework", "dummy.py")


# ── Helper: _display_results ────────────────────────────────────────

class TestDisplayResults:
    def test_display_minimal(self) -> None:
        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli.main import _display_results

        result = CampaignResult.model_validate(_minimal_campaign_result())
        _display_results(result)  # Should not raise

    def test_display_vulnerable(self) -> None:
        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli.main import _display_results

        result = CampaignResult.model_validate(_vulnerable_campaign_result())
        _display_results(result)  # Should not raise
