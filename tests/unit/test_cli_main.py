"""Tests for CLI commands — exercises every Click command via CliRunner.

Covers: scan, discover, library, report, poc, policy, audit, ci, plus
display and save helpers. Factory functions (load_agent_adapter,
load_remote_adapter, build_strategy) are in ziran.application.factories.

Every external side-effect (file I/O, asyncio.run, adapter loading) is
mocked so these tests are fast and deterministic.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli


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

    @patch("ziran.interfaces.cli.main.load_agent_adapter")
    @patch("ziran.interfaces.cli.main.AgentScanner")
    @patch("ziran.interfaces.cli.main.asyncio")
    def test_scan_local_success(
        self,
        mock_asyncio: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_load: MagicMock,
        runner: CliRunner,
    ) -> None:
        """Scan with --framework + --agent-path should go through the local path."""
        mock_adapter = MagicMock()
        mock_load.return_value = mock_adapter

        # Create a minimal CampaignResult-like object
        from ziran.domain.entities.phase import CampaignResult

        result_data = _minimal_campaign_result()
        mock_result = CampaignResult.model_validate(result_data)
        mock_asyncio.run.return_value = mock_result

        # Mock AgentScanner so run_campaign doesn't create a real coroutine
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("agent_executor = None\n")
            f.flush()
            runner.invoke(
                cli,
                [
                    "scan",
                    "--framework",
                    "langchain",
                    "--agent-path",
                    f.name,
                    "--output",
                    tempfile.mkdtemp(),
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
        assert "--resume" in result.output


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

    def test_audit_json_output_shape(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text('api_key = "abcdefghijklmnop"\n')
        result = runner.invoke(cli, ["audit", str(src), "--format", "json"])
        assert result.exit_code == 1
        assert "abcdefghijklmnop" not in result.stdout
        data = json.loads(result.stdout)
        assert data["files_analyzed"] == 1
        [finding] = data["findings"]
        assert set(finding) == {"rule", "severity", "file", "line", "message"}
        assert finding["rule"] == "SA001"
        assert finding["severity"] == "critical"
        assert finding["line"] == 1

    def test_audit_json_exit_nonzero_at_severity(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text('def q(cur, x):\n    cur.execute(f"SELECT * FROM t WHERE id = {x}")\n')
        high = runner.invoke(cli, ["audit", str(src), "--format", "json", "--severity", "high"])
        assert high.exit_code == 1
        assert len(json.loads(high.stdout)["findings"]) == 1
        crit = runner.invoke(cli, ["audit", str(src), "--format", "json", "--severity", "critical"])
        assert crit.exit_code == 0
        assert json.loads(crit.stdout)["findings"] == []

    def test_audit_json_clean_file(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text("x = 1\n")
        result = runner.invoke(cli, ["audit", str(src), "--format", "json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout) == {"files_analyzed": 1, "findings": []}

    # ── Claude Code plugins (spec 038) ──

    def _json(self, runner: CliRunner, *args: str) -> tuple[int, dict[str, Any], str]:
        result = runner.invoke(cli, ["audit", *args, "--format", "json"])
        return result.exit_code, json.loads(result.stdout), result.stdout

    def test_audit_claude_code_vulnerable_json(self, runner: CliRunner) -> None:
        code, data, _ = self._json(runner, str(CC_FIXTURES / "vulnerable_plugin"))
        assert code == 1
        assert data["files_analyzed"] == 5
        rows = data["findings"]
        assert all(set(r) == CC_KEYS for r in rows)
        [chain] = [
            r
            for r in rows
            if r["rule"] == "CC001"
            and r["agent"] == "researcher"
            and r["tools"] == ["Read", "WebFetch"]
        ]
        assert chain["severity"] == "critical"
        assert chain["line"] == 4
        assert chain["file"].endswith("researcher.md")
        assert "data_exfiltration" in chain["message"]
        assert "Read -> WebFetch" in chain["message"]
        [sa007] = [r for r in rows if r["rule"] == "SA007"]
        assert (sa007["agent"], sa007["line"], sa007["severity"]) == ("generalist", 1, "high")
        assert any(
            r["rule"] == "CC001" and r["agent"] == "generalist" and r["tools"] == ["Bash"]
            for r in rows
        )

    def test_audit_claude_code_vulnerable_text(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["audit", str(CC_FIXTURES / "vulnerable_plugin")])
        assert result.exit_code == 1
        assert "CC001" in result.output
        assert "SA007" in result.output

    def test_audit_claude_code_safe(self, runner: CliRunner) -> None:
        safe = str(CC_FIXTURES / "safe_plugin")
        assert runner.invoke(cli, ["audit", safe]).exit_code == 0
        for extra in ([], ["--severity", "low"]):
            code, data, _ = self._json(runner, safe, *extra)
            assert code == 0
            assert data == {"files_analyzed": 5, "findings": []}

    def test_audit_claude_code_malformed(self, runner: CliRunner) -> None:
        code, data, out = self._json(runner, str(CC_FIXTURES / "malformed"), "--severity", "high")
        assert code == 1
        [row] = data["findings"]
        assert row["rule"] == "CC000"
        assert row["line"] == 3
        assert row["file"].endswith("broken.md")
        assert row["agent"] is None
        assert row["tools"] == []
        assert "ziran-fake-secret-0416" not in out

    def test_audit_claude_code_secret_redacted(self, runner: CliRunner, tmp_path: Path) -> None:
        _write_agent(tmp_path / "agents", "leaky", "Read", 'api_key = "ziran-fake-secret-0418"')
        code, data, out = self._json(runner, str(tmp_path))
        assert code == 1
        [row] = [r for r in data["findings"] if r["rule"] == "SA001"]
        assert row["line"] == 6
        assert row["agent"] == "leaky"
        assert "ziran-fake-secret-0418" not in out

    def test_audit_claude_code_single_file(self, runner: CliRunner, tmp_path: Path) -> None:
        md = _write_agent(tmp_path, "shell", "Bash")
        _, data, _ = self._json(runner, str(md))
        assert data["files_analyzed"] == 1
        sa003 = [r for r in data["findings"] if r["rule"] == "SA003"]
        assert [r["tools"] for r in sa003] == [["Bash"]]

    def test_audit_mixed_python_and_agents(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text('api_key = "abcdefghijklmnop"\n')
        _write_agent(tmp_path / ".claude" / "agents", "a", "Read, WebFetch")
        code, data, _ = self._json(runner, str(tmp_path))
        assert code == 1
        rules = [r["rule"] for r in data["findings"]]
        py = data["findings"][rules.index("SA001")]
        assert py["file"].endswith("agent.py")
        assert (py["agent"], py["tools"]) == (None, [])
        assert rules.index("SA001") < rules.index("CC001")

    def test_audit_json_python_keys_unchanged(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text('api_key = "abcdefghijklmnop"\n')
        _, data, _ = self._json(runner, str(tmp_path))
        assert data["findings"]
        assert all(
            set(r) == {"rule", "severity", "file", "line", "message"} for r in data["findings"]
        )

    def test_audit_wuwei_agents_dir_widening(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        _write_agent(agents, "builder", "Read, Grep")
        code, data, _ = self._json(runner, str(agents), "--severity", "high")
        assert code == 0
        assert not [r for r in data["findings"] if r["rule"] == "CC001"]
        _write_agent(agents, "builder", "Read, Grep, WebFetch")
        code, data, _ = self._json(runner, str(agents), "--severity", "high")
        assert code == 1
        assert any(
            r["rule"] == "CC001"
            and r["severity"] == "critical"
            and r["agent"] == "builder"
            and "Read -> WebFetch" in r["message"]
            for r in data["findings"]
        )


CC_FIXTURES = Path(__file__).parents[1] / "fixtures" / "claude_code"
CC_KEYS = {"rule", "severity", "file", "line", "message", "agent", "tools"}


def _write_agent(directory: Path, name: str, tools: str, body: str = "Do the job.") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    md = directory / f"{name}.md"
    md.write_text(f"---\nname: {name}\ndescription: test agent\ntools: {tools}\n---\n{body}\n")
    return md


# ── ci command ──────────────────────────────────────────────────────


class TestCiCommand:
    def test_ci_minimal_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            result = runner.invoke(
                cli, ["ci", f.name, "--no-github-annotations", "--no-github-summary"]
            )
        assert result.exit_code in (0, 1)

    def test_ci_with_sarif(self, runner: CliRunner, tmp_path: Path) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_minimal_campaign_result(), f)
            f.flush()
            sarif_path = str(tmp_path / "out.sarif")
            result = runner.invoke(
                cli,
                [
                    "ci",
                    f.name,
                    "--sarif",
                    sarif_path,
                    "--no-github-annotations",
                    "--no-github-summary",
                ],
            )
        assert result.exit_code in (0, 1)

    def test_ci_invalid_result(self, runner: CliRunner) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("bad")
            f.flush()
            result = runner.invoke(cli, ["ci", f.name])
        assert result.exit_code != 0


# ── Helper: _load_python_object (now in ziran.application.factories) ──


class TestLoadPythonObject:
    def test_load_existing_object(self) -> None:
        from ziran.application.factories import _load_python_object

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("my_var = 42\n")
            f.flush()
            obj = _load_python_object(f.name, "my_var")
        assert obj == 42

    def test_load_missing_object(self) -> None:
        from ziran.application.factories import _load_python_object

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n")
            f.flush()
            with pytest.raises(ValueError, match="not found"):
                _load_python_object(f.name, "nonexistent")

    def test_load_missing_file(self) -> None:
        from ziran.application.factories import _load_python_object

        with pytest.raises(FileNotFoundError, match=r"not found|No such file"):
            _load_python_object("/nonexistent/path.py", "obj")


# ── Helper: _load_bedrock_config (now in ziran.application.factories) ──


class TestLoadBedrockConfig:
    def test_load_agent_id_string(self) -> None:
        from ziran.application.factories import _load_bedrock_config

        result = _load_bedrock_config("my-agent-id")
        assert result == {"agent_id": "my-agent-id"}

    def test_load_yaml_config(self) -> None:
        from ziran.application.factories import _load_bedrock_config

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("agent_id: abc123\nregion_name: us-east-1\n")
            f.flush()
            result = _load_bedrock_config(f.name)
        assert result["agent_id"] == "abc123"
        assert result["region_name"] == "us-east-1"

    def test_load_invalid_yaml_config(self) -> None:
        from ziran.application.factories import _load_bedrock_config

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("- just_a_list\n")
            f.flush()
            with pytest.raises(ValueError, match="agent_id"):
                _load_bedrock_config(f.name)


# ── Helper: load_agent_adapter (now in ziran.application.factories) ──


class TestLoadAgentAdapter:
    def test_unsupported_framework(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with pytest.raises(ValueError, match="Unsupported"):
            load_agent_adapter("unknown_framework", "dummy.py")


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


# ── dry-run mode ──────────────────────────────────────────────────────


class TestDryRun:
    def test_scan_help_includes_dry_run(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--dry-run" in result.output

    @patch("ziran.interfaces.cli.main.load_agent_adapter")
    @patch("ziran.interfaces.cli.main.asyncio")
    def test_dry_run_does_not_execute_campaign(
        self, mock_asyncio: MagicMock, mock_load: MagicMock, runner: CliRunner
    ) -> None:
        """--dry-run should NOT call scanner.run_campaign."""
        mock_adapter = MagicMock()
        mock_load.return_value = mock_adapter

        # discover_capabilities returns a list of capabilities
        mock_cap = MagicMock()
        mock_cap.dangerous = True
        mock_asyncio.run.return_value = [mock_cap]

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("agent_executor = None\n")
            f.flush()
            result = runner.invoke(
                cli,
                [
                    "scan",
                    "--framework",
                    "langchain",
                    "--agent-path",
                    f.name,
                    "--dry-run",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0
        assert "Dry Run Summary" in result.output or "Configuration valid" in result.output

    @patch("ziran.interfaces.cli.main.load_remote_adapter")
    @patch("ziran.interfaces.cli.main.asyncio")
    def test_dry_run_remote_target(
        self, mock_asyncio: MagicMock, mock_load: MagicMock, runner: CliRunner
    ) -> None:
        """--dry-run with --target should load adapter and show summary."""
        mock_adapter = MagicMock()
        mock_config = MagicMock()
        mock_config.url = "https://agent.example.com"
        mock_config.protocol.value = "openai"
        mock_config.auth = None
        mock_load.return_value = (mock_adapter, mock_config)

        mock_cap = MagicMock()
        mock_cap.dangerous = False
        mock_asyncio.run.return_value = [mock_cap]

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("url: https://agent.example.com\n")
            f.flush()
            result = runner.invoke(
                cli,
                ["scan", "--target", f.name, "--dry-run"],
                catch_exceptions=False,
            )

        assert result.exit_code == 0


# ── config validation warnings ────────────────────────────────────────


class TestConfigValidationWarnings:
    def test_attack_timeout_exceeds_phase_timeout(self) -> None:
        from ziran.interfaces.cli.main import _warn_config_issues

        # Should not raise — just prints warnings
        _warn_config_issues(
            attack_timeout=600.0,
            phase_timeout=300.0,
            concurrency=5,
            strategy="fixed",
            llm_provider=None,
            encoding=(),
        )

    def test_high_concurrency_warning(self) -> None:
        from ziran.interfaces.cli.main import _warn_config_issues

        _warn_config_issues(
            attack_timeout=60.0,
            phase_timeout=300.0,
            concurrency=100,
            strategy="fixed",
            llm_provider=None,
            encoding=(),
        )

    def test_llm_adaptive_without_provider(self) -> None:
        from ziran.interfaces.cli.main import _warn_config_issues

        _warn_config_issues(
            attack_timeout=60.0,
            phase_timeout=300.0,
            concurrency=5,
            strategy="llm-adaptive",
            llm_provider=None,
            encoding=(),
        )

    def test_no_warnings_with_valid_config(self) -> None:
        from ziran.interfaces.cli.main import _warn_config_issues

        # Should produce no warnings
        _warn_config_issues(
            attack_timeout=60.0,
            phase_timeout=300.0,
            concurrency=5,
            strategy="fixed",
            llm_provider=None,
            encoding=(),
        )


# ── validate command ──────────────────────────────────────────────────


class TestValidateCommand:
    def test_validate_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0
        assert "Validate" in result.output or "validate" in result.output

    def test_validate_valid_yaml(self, runner: CliRunner) -> None:
        """Valid YAML config should pass parse and schema checks."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("url: https://agent.example.com\nprotocol: openai\n")
            f.flush()
            result = runner.invoke(cli, ["validate", f.name])

        # URL is not actually reachable, but parse+schema should pass
        assert "YAML parse" in result.output
        assert "Config schema" in result.output

    def test_validate_invalid_yaml(self, runner: CliRunner) -> None:
        """Invalid YAML should fail with a clear error."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("{{not: valid: yaml:::\n")
            f.flush()
            result = runner.invoke(cli, ["validate", f.name])

        assert result.exit_code != 0

    def test_validate_invalid_schema(self, runner: CliRunner) -> None:
        """Valid YAML but missing required fields should fail schema validation."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("name: missing_url_field\n")
            f.flush()
            result = runner.invoke(cli, ["validate", f.name])

        assert result.exit_code != 0
