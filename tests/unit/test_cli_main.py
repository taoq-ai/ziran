"""Tests for CLI commands — exercises every Click command via CliRunner.

Covers: scan, discover, library, report, poc, policy, audit, ci, plus
display and save helpers. Factory functions (load_agent_adapter,
load_remote_adapter, build_strategy) are in ziran.application.factories.

Every external side-effect (file I/O, asyncio.run, adapter loading) is
mocked so these tests are fast and deterministic.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, ClassVar
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


class TestAuditBaseline:
    """Allowlist baseline (spec 039)."""

    BUILDER = "Read, Glob, Grep, Bash, Write, Edit"

    def _run(self, runner: CliRunner, *args: str) -> tuple[int, dict[str, Any], str]:
        result = runner.invoke(cli, ["audit", *args, "--format", "json"])
        return result.exit_code, json.loads(result.stdout), result.output

    def _plugin(self, tmp_path: Path) -> Path:
        dst = tmp_path / "plugin"
        shutil.copytree(CC_FIXTURES / "vulnerable_plugin", dst)
        return dst

    def _record(self, runner: CliRunner, target: Path, baseline: Path) -> int:
        args = ["audit", str(target), "--write-baseline", str(baseline)]
        return runner.invoke(cli, args).exit_code

    @staticmethod
    def _bl(data: dict[str, Any]) -> list[dict[str, Any]]:
        return [r for r in data["findings"] if r["rule"].startswith("BL")]

    def test_write_baseline(self, runner: CliRunner, tmp_path: Path) -> None:
        plugin = self._plugin(tmp_path)
        b = tmp_path / "baseline.json"
        for extra in ([], ["--severity", "low"]):
            code, data, out = self._run(runner, str(plugin), "--write-baseline", str(b), *extra)
            assert code == 0
            assert data["findings"] == []
            assert data["baseline"] == {"narrowed": []}
            assert "Baseline written to" in out
        first = b.read_bytes()
        assert self._record(runner, plugin, b) == 0
        assert b.read_bytes() == first
        doc = json.loads(first)
        assert doc["version"] == 1
        assert list(doc["agents"]) == ["generalist", "researcher"]
        assert doc["agents"]["generalist"]["tools"] is None
        assert {
            "tools": ["Read", "WebFetch"],
            "vulnerability_type": "data_exfiltration",
            "severity": "critical",
        } in doc["agents"]["researcher"]["chains"]
        assert "summary to the team channel" not in first.decode()

    def test_wuwei_widening_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        md = _write_agent(agents, "builder", self.BUILDER)
        b = tmp_path / "baseline.json"
        assert self._record(runner, agents, b) == 0
        md.write_text(md.read_text().replace(self.BUILDER, self.BUILDER + ", WebFetch"))
        for extra in ([], ["--severity", "critical"], ["--severity", "high"]):
            code, data, _ = self._run(runner, str(agents), "--baseline", str(b), *extra)
            assert code == 1
            bl = self._bl(data)
            [bl001] = [r for r in bl if r["rule"] == "BL001"]
            assert (bl001["tools"], bl001["line"], bl001["agent"]) == (["WebFetch"], 4, "builder")
            assert bl001["severity"] == "critical"
            [rw] = [r for r in bl if r["rule"] == "BL003" and r["tools"] == ["Read", "WebFetch"]]
            assert rw["message"] == (
                "Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch "
                "not in the baseline"
            )
            assert all(set(r) == CC_KEYS for r in data["findings"])
        text = runner.invoke(cli, ["audit", str(agents), "--baseline", str(b)])
        assert text.exit_code == 1
        for needle in ("builder", "WebFetch", "Read -> WebFetch"):
            assert needle in text.output

    def test_narrowing_passes(self, runner: CliRunner, tmp_path: Path) -> None:
        plugin = self._plugin(tmp_path)
        b = tmp_path / "baseline.json"
        assert self._record(runner, plugin, b) == 0
        md = plugin / "agents" / "researcher.md"
        md.write_text(md.read_text().replace("WebFetch, ", ""))
        for extra in ([], ["--severity", "low"]):
            code, data, _ = self._run(runner, str(plugin), "--baseline", str(b), *extra)
            assert code == 0
            assert not self._bl(data)
            assert {
                "agent": "researcher",
                "change": "tool_removed",
                "tools": ["WebFetch"],
            } in data["baseline"]["narrowed"]
        text = runner.invoke(cli, ["audit", str(plugin), "--baseline", str(b)])
        assert text.exit_code == 0
        for needle in ("Baseline narrowed", "researcher", "tool_removed", "WebFetch"):
            assert needle in text.output

    def test_tools_key_removed(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        md = _write_agent(agents, "builder", "Read")
        b = tmp_path / "baseline.json"
        assert self._record(runner, agents, b) == 0
        md.write_text(md.read_text().replace("tools: Read\n", ""))
        code, data, _ = self._run(runner, str(agents), "--baseline", str(b))
        assert code == 1
        assert self._bl(data)[0]["rule"] == "BL002"

    def test_new_agent(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        _write_agent(agents, "builder", "Read")
        b = tmp_path / "baseline.json"
        assert self._record(runner, agents, b) == 0
        _write_agent(agents, "helper", "Grep")
        code, data, _ = self._run(runner, str(agents), "--baseline", str(b))
        assert code == 1
        assert [(r["rule"], r["agent"]) for r in self._bl(data)] == [("BL004", "helper")]

    def test_chain_deleted_from_baseline(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        _write_agent(agents, "builder", self.BUILDER)
        b = tmp_path / "baseline.json"
        assert self._record(runner, agents, b) == 0
        doc = json.loads(b.read_text())
        dropped = doc["agents"]["builder"]["chains"].pop(0)
        b.write_text(json.dumps(doc))
        code, data, _ = self._run(runner, str(agents), "--baseline", str(b))
        assert code == 1
        assert [(r["rule"], r["tools"]) for r in self._bl(data)] == [("BL003", dropped["tools"])]

    def test_malformed_escalated(self, runner: CliRunner, tmp_path: Path) -> None:
        malformed = str(CC_FIXTURES / "malformed")
        b = tmp_path / "baseline.json"
        assert self._record(runner, CC_FIXTURES / "malformed", b) == 1
        assert runner.invoke(cli, ["audit", malformed, "--baseline", str(b)]).exit_code == 1
        code, data, out = self._run(runner, malformed, "--baseline", str(b))
        assert code == 1
        [cc000] = [r for r in data["findings"] if r["rule"] == "CC000"]
        assert cc000["severity"] == "critical"
        assert "ziran-fake-secret-0416" not in out

    def test_usage_errors(self, runner: CliRunner, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        _write_agent(agents, "builder", "Read")
        b = tmp_path / "baseline.json"
        assert self._record(runner, agents, b) == 0

        def run(*args: str) -> tuple[int, str]:
            r = runner.invoke(cli, ["audit", *args])
            return r.exit_code, r.output

        assert run(str(agents), "--baseline", str(b), "--write-baseline", str(b))[0] == 2
        assert run(str(agents), "--baseline", str(tmp_path / "missing.json"))[0] == 2
        bad = tmp_path / "bad.json"
        bad.write_text("{not json ziran-fake-secret-0419")
        rc, out = run(str(agents), "--baseline", str(bad))
        assert rc == 2
        assert "ziran-fake-secret-0419" not in out
        bad.write_text('{"agents": {}}')
        rc, out = run(str(agents), "--baseline", str(bad))
        assert rc == 2
        assert "version" in out
        bad.write_text('{"version": 1, "agents": {"x": {"tools": "ziran-fake-secret-0419"}}}')
        rc, out = run(str(agents), "--baseline", str(bad))
        assert rc == 2
        assert "ziran-fake-secret-0419" not in out
        py = tmp_path / "py"
        py.mkdir()
        (py / "agent.py").write_text("x = 1\n")
        assert run(str(py), "--baseline", str(b))[0] == 2
        never = tmp_path / "never.json"
        assert run(str(py), "--write-baseline", str(never))[0] == 2
        assert not never.exists()
        assert run(str(agents), "--write-baseline", str(tmp_path / "no" / "dir.json"))[0] == 2

    def test_no_baseline_key_without_flags(self, runner: CliRunner, tmp_path: Path) -> None:
        _, data, _ = self._run(runner, str(CC_FIXTURES / "safe_plugin"))
        assert "baseline" not in data
        (tmp_path / "agent.py").write_text("x = 1\n")
        _, data, _ = self._run(runner, str(tmp_path))
        assert "baseline" not in data


SAMPLE_PLUGIN = Path(__file__).parents[2] / "examples/07-cicd-quality-gate/claude-code-plugin"


class TestAuditSarif:
    """``ziran audit --sarif`` (spec 040)."""

    @pytest.fixture(autouse=True)
    def _cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _plug(widen: bool = False) -> Path:
        dst = Path("plug")
        shutil.copytree(SAMPLE_PLUGIN, dst)
        if widen:
            md = dst / "agents" / "builder.md"
            lines = md.read_text().splitlines(keepends=True)
            lines[3] = lines[3].rstrip("\n") + ", WebFetch\n"
            md.write_text("".join(lines))
        return dst

    @staticmethod
    def _sarif(path: str = "out.sarif") -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = json.loads(Path(path).read_text())["runs"][0]["results"]
        return results

    def _audit(self, runner: CliRunner, *args: str) -> Any:
        return runner.invoke(
            cli, ["audit", "plug", "--baseline", "plug/ziran-baseline.json", *args]
        )

    def test_sample_passes_with_baseline(self, runner: CliRunner) -> None:
        self._plug()
        result = self._audit(runner, "--format", "json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["findings"] == []

    def test_sample_baseline_is_current(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "b.json"
        result = runner.invoke(cli, ["audit", str(SAMPLE_PLUGIN), "--write-baseline", str(out)])
        assert result.exit_code == 0
        assert out.read_bytes() == (SAMPLE_PLUGIN / "ziran-baseline.json").read_bytes()

    def test_widened_agent_in_sarif(self, runner: CliRunner) -> None:
        self._plug(widen=True)
        result = self._audit(runner, "--sarif", "out.sarif")
        assert result.exit_code == 1
        results = self._sarif()
        [bl001] = [r for r in results if r["ruleId"] == "BL001"]
        assert bl001["message"]["text"] == (
            "Agent 'builder' gains tool 'WebFetch' not in the baseline"
        )
        loc = bl001["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "plug/agents/builder.md"
        assert loc["region"]["startLine"] == 4
        assert (
            "Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch "
            "not in the baseline"
            in [r["message"]["text"] for r in results if r["ruleId"] == "BL003"]
        )

    def test_json_stdout_unchanged(self, runner: CliRunner) -> None:
        self._plug(widen=True)
        plain = self._audit(runner, "--format", "json")
        with_sarif = self._audit(runner, "--format", "json", "--sarif", "out.sarif")
        assert with_sarif.exit_code == plain.exit_code == 1
        assert json.loads(with_sarif.stdout) == json.loads(plain.stdout)
        assert "SARIF written to out.sarif" in with_sarif.stderr
        rows = json.loads(plain.stdout)["findings"]
        assert [r["ruleId"] for r in self._sarif()] == [r["rule"] for r in rows]

    def test_text_mode_writes_before_exit(self, runner: CliRunner) -> None:
        self._plug(widen=True)
        assert self._audit(runner, "--sarif", "out.sarif").exit_code == 1
        assert Path("out.sarif").exists()

    def test_severity_filter_applies(self, runner: CliRunner) -> None:
        self._plug(widen=True)
        runner.invoke(cli, ["audit", "plug", "--severity", "critical", "--sarif", "out.sarif"])
        results = self._sarif()
        assert results
        assert "SA003" not in {r["ruleId"] for r in results}

    def test_narrowing_gives_empty_results(self, runner: CliRunner) -> None:
        plug = self._plug()
        md = plug / "agents" / "researcher.md"
        md.write_text(md.read_text().replace(", Glob", ""))
        result = self._audit(runner, "--sarif", "out.sarif")
        assert result.exit_code == 0
        assert self._sarif() == []

    def test_unwritable_sarif_is_usage_error(self, runner: CliRunner, tmp_path: Path) -> None:
        self._plug()
        result = self._audit(runner, "--sarif", str(tmp_path / "missing-dir" / "x.sarif"))
        assert result.exit_code == 2
        assert "Traceback" not in result.output
        assert "--sarif" in result.output

    def test_python_rows(self, runner: CliRunner) -> None:
        Path("py").mkdir()
        Path("py/agent.py").write_text('api_key = "abcdefghijklmnop"\n')
        result = runner.invoke(cli, ["audit", "py", "--format", "json", "--sarif", "out.sarif"])
        assert result.exit_code == 1
        rows = json.loads(result.stdout)["findings"]
        results = self._sarif()
        assert [r["ruleId"] for r in results] == [r["rule"] for r in rows] == ["SA001"]
        assert "abcdefghijklmnop" not in Path("out.sarif").read_text()


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

    @pytest.mark.parametrize("with_tiers", [True, False])
    def test_display_judge_routing_row(self, with_tiers: bool) -> None:
        from rich.console import Console

        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli.main import _display_results

        data = _minimal_campaign_result()
        if with_tiers:
            data["metadata"] = {"judge_tiers": {"deterministic": 3, "cheap": 2, "escalated": 1}}
        rec = Console(record=True, width=200)
        with patch("ziran.interfaces.cli.main.console", rec):
            _display_results(CampaignResult.model_validate(data))
        out = rec.export_text()
        assert ("Judge Routing" in out) is with_tiers
        assert ("deterministic 3 · cheap 2 · escalated 1" in out) is with_tiers


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


@pytest.mark.unit
class TestScanDetectorConfig:
    """`_scan_detector_config` builds the ensemble config for `ziran scan` (spec 041)."""

    _ENSEMBLE = (
        "hit: 0.8\n"
        "ensemble:\n"
        "  enabled: true\n"
        "  judges:\n"
        "    - name: primary\n"
        "    - name: second\n"
        "      model: m2\n"
    )

    @pytest.fixture
    def calls(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[dict[str, Any]]:
        recorded: list[dict[str, Any]] = []

        def _create(**kwargs: Any) -> Any:
            recorded.append(kwargs)
            return MagicMock(name=f"client-{kwargs['model']}")

        monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", _create)
        monkeypatch.chdir(tmp_path)
        return recorded

    @staticmethod
    def _write(text: str) -> None:
        Path(".ziran").mkdir(exist_ok=True)
        Path(".ziran/detectors.yaml").write_text(text, encoding="utf-8")

    @staticmethod
    def _call() -> Any:
        from ziran.interfaces.cli.main import _scan_detector_config

        return _scan_detector_config(
            llm_provider="litellm", llm_rpm=10, llm_tpm=1000, llm_max_retries=2
        )

    def test_no_file_returns_none(self, calls: list[dict[str, Any]]) -> None:
        assert self._call() is None

    def test_disabled_returns_none(self, calls: list[dict[str, Any]]) -> None:
        self._write("hit: 0.8\nensemble:\n  enabled: false\n")
        assert self._call() is None

    def test_enabled_builds_config(self, calls: list[dict[str, Any]]) -> None:
        from ziran.application.detectors.thresholds import DetectorThresholds
        from ziran.infrastructure.config.detectors import load_detector_thresholds

        self._write(self._ENSEMBLE)
        config = self._call()
        assert config.thresholds.ensemble == load_detector_thresholds().ensemble
        assert config.thresholds.hit == DetectorThresholds().hit
        assert list(config.judge_clients) == ["second"]
        assert calls == [
            {"provider": "litellm", "model": "m2", "rpm": 10, "tpm": 1000, "max_retries": 2}
        ]

    def test_invalid_file_raises(self, calls: list[dict[str, Any]]) -> None:
        import click

        self._write("ensemble:\n  enabled: true\n  judges:\n    - name: a\n")
        with pytest.raises(click.ClickException, match="ensemble"):
            self._call()

    def test_client_failure_raises(
        self, calls: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import click

        def _boom(**kwargs: Any) -> Any:
            raise RuntimeError("no key")

        monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", _boom)
        self._write(self._ENSEMBLE)
        with pytest.raises(click.ClickException, match="no key"):
            self._call()

    def test_prefilter_only(self, calls: list[dict[str, Any]]) -> None:
        self._write("prefilter:\n  enabled: true\n  model: m\n")
        config = self._call()
        assert config.thresholds.prefilter.model == "m"
        assert config.judge_clients == {}
        assert config.prefilter_client is not None
        assert calls == [
            {"provider": "litellm", "model": "m", "rpm": 10, "tpm": 1000, "max_retries": 2}
        ]

    def test_prefilter_provider_override(self, calls: list[dict[str, Any]]) -> None:
        self._write("prefilter:\n  enabled: true\n  model: m\n  provider: other\n")
        self._call()
        assert calls[0]["provider"] == "other"

    def test_both_disabled_returns_none(self, calls: list[dict[str, Any]]) -> None:
        self._write("prefilter:\n  enabled: false\nensemble:\n  enabled: false\n")
        assert self._call() is None
        assert calls == []

    def test_prefilter_without_model_raises(self, calls: list[dict[str, Any]]) -> None:
        import click

        self._write("prefilter:\n  enabled: true\n")
        with pytest.raises(click.ClickException, match="prefilter"):
            self._call()

    def test_prefilter_client_failure_raises(
        self, calls: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import click

        def _boom(**kwargs: Any) -> Any:
            raise ImportError("litellm missing")

        monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", _boom)
        self._write("prefilter:\n  enabled: true\n  model: m\n")
        with pytest.raises(click.ClickException, match=r"^cannot create prefilter client:"):
            self._call()

    def test_disabled_ensemble_members_not_built(self, calls: list[dict[str, Any]]) -> None:
        self._write(
            "ensemble:\n  enabled: false\n  judges:\n    - name: a\n      model: ma\n"
            "    - name: b\n      model: mb\n"
            "prefilter:\n  enabled: true\n  model: m\n"
        )
        config = self._call()
        assert config.judge_clients == {}
        assert [c["model"] for c in calls] == ["m"]

    @patch("ziran.interfaces.cli.main.load_agent_adapter")
    @patch("ziran.interfaces.cli.main.AgentScanner")
    @patch("ziran.interfaces.cli.main.asyncio")
    def test_scan_wires_prefilter(
        self,
        mock_asyncio: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_load: MagicMock,
        calls: list[dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        from ziran.domain.entities.phase import CampaignResult

        self._write("prefilter:\n  enabled: true\n  model: m\n")
        mock_asyncio.run.return_value = CampaignResult.model_validate(_minimal_campaign_result())
        agent = tmp_path / "agent.py"
        agent.write_text("agent_executor = None\n", encoding="utf-8")
        result = CliRunner().invoke(
            cli,
            [
                "scan",
                "--framework",
                "langchain",
                "--agent-path",
                str(agent),
                "--llm-provider",
                "litellm",
                "--output",
                str(tmp_path / "out"),
            ],
            catch_exceptions=False,
        )
        scanner_config = mock_scanner_cls.call_args.kwargs["config"]
        assert scanner_config["detector_config"].prefilter_client is not None
        assert "LLM judge prefilter: m" in result.output
        assert "LLM judge ensemble" not in result.output


@pytest.mark.unit
class TestScanEnsembleWiring:
    """`ziran scan` passes the ensemble config to the scanner (spec 041 US4.4, US5.1, US5.2)."""

    @pytest.fixture
    def scanner_cls(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> MagicMock:
        from ziran.domain.entities.phase import CampaignResult

        monkeypatch.chdir(tmp_path)
        Path("agent.py").write_text("agent_executor = None\n", encoding="utf-8")
        monkeypatch.setattr(
            "ziran.infrastructure.llm.create_llm_client", lambda **kw: MagicMock(name="client")
        )
        monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
        mock_asyncio = MagicMock()
        mock_asyncio.run.return_value = CampaignResult.model_validate(_minimal_campaign_result())
        monkeypatch.setattr("ziran.interfaces.cli.main.asyncio", mock_asyncio)
        cls = MagicMock()
        monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", cls)
        return cls

    @staticmethod
    def _scan(runner: CliRunner, yaml_text: str, *extra: str) -> Any:
        Path(".ziran").mkdir()
        Path(".ziran/detectors.yaml").write_text(yaml_text, encoding="utf-8")
        args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", *extra]
        return runner.invoke(cli, [*args, "--output", "out"])

    def test_enabled_block_reaches_scanner(self, runner: CliRunner, scanner_cls: MagicMock) -> None:
        result = self._scan(runner, TestScanDetectorConfig._ENSEMBLE, "--llm-model", "m1")
        assert result.exit_code == 0, result.output
        config = scanner_cls.call_args.kwargs["config"]
        assert [j.name for j in config["detector_config"].thresholds.ensemble.judges] == [
            "primary",
            "second",
        ]
        assert list(config["detector_config"].judge_clients) == ["second"]

    def test_invalid_block_exits_1(self, runner: CliRunner, scanner_cls: MagicMock) -> None:
        bad = "ensemble:\n  enabled: true\n  min_margin: 0\n"
        result = self._scan(runner, bad, "--llm-model", "m1")
        assert result.exit_code == 1
        assert "min_margin" in result.output
        scanner_cls.assert_not_called()

    def test_file_not_read_without_llm(self, runner: CliRunner, scanner_cls: MagicMock) -> None:
        result = self._scan(runner, "ensemble: [not, a, mapping\n")
        assert result.exit_code == 0, result.output
        assert "detector_config" not in scanner_cls.call_args.kwargs["config"]


# ── Spec 047: token budget and cost cap on `ziran scan` ──────────────


def _flat(text: str) -> str:
    return " ".join(text.split())


def _cli_usage_stub(model: str) -> Any:
    from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

    class _UsageStub(BaseLLMClient):
        def __init__(self) -> None:
            super().__init__(LLMConfig(model=model))

        async def complete(self, messages: list[dict[str, str]], **kw: Any) -> LLMResponse:
            return LLMResponse(content="{}", prompt_tokens=100, completion_tokens=20)

        async def health_check(self) -> bool:
            return True

    return _UsageStub()


@pytest.mark.unit
class TestScanBudgetWiring:
    """`ziran scan` budget flags, client tracking and output (spec 047 US4.3, US5.1-US5.4)."""

    _DETECTORS = (
        "ensemble:\n"
        "  enabled: true\n"
        "  judges:\n"
        "    - name: primary\n"
        "    - name: second\n"
        "      model: m2\n"
        "prefilter:\n"
        "  enabled: true\n"
        "  model: cheap\n"
    )

    @pytest.fixture
    def env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
        from ziran.domain.entities.phase import CampaignResult

        monkeypatch.chdir(tmp_path)
        Path("agent.py").write_text("agent_executor = None\n", encoding="utf-8")
        monkeypatch.setattr(
            "ziran.infrastructure.llm.create_llm_client",
            lambda **kw: _cli_usage_stub(kw["model"]),
        )
        monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
        mock_asyncio = MagicMock()
        mock_asyncio.run.return_value = CampaignResult.model_validate(_minimal_campaign_result())
        monkeypatch.setattr("ziran.interfaces.cli.main.asyncio", mock_asyncio)
        scanner_cls = MagicMock()
        monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", scanner_cls)
        strategy = MagicMock()
        monkeypatch.setattr("ziran.interfaces.cli.main.build_strategy", strategy)
        return {"scanner": scanner_cls, "strategy": strategy, "asyncio": mock_asyncio}

    @staticmethod
    def _scan(runner: CliRunner, *extra: str) -> Any:
        args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", *extra]
        return runner.invoke(cli, [*args, "--output", "out"])

    def test_flags_and_tracked_clients(self, runner: CliRunner, env: dict[str, Any]) -> None:
        from ziran.application.usage import UsageLedger
        from ziran.infrastructure.llm.usage_tracking_client import UsageTrackingClient

        Path(".ziran").mkdir()
        Path(".ziran/detectors.yaml").write_text(self._DETECTORS, encoding="utf-8")
        result = self._scan(
            runner,
            "--llm-model",
            "m1",
            "--max-campaign-tokens",
            "50000",
            "--max-cost",
            "2.5",
        )
        assert result.exit_code == 0, result.output
        config = env["scanner"].call_args.kwargs["config"]
        assert config["max_campaign_tokens"] == 50000
        assert config["max_cost"] == 2.5
        ledger = config["usage_ledger"]
        assert isinstance(ledger, UsageLedger)
        assert "50,000 tokens · $2.5" in _flat(result.output)
        judge = config["llm_client"]
        assert isinstance(judge, UsageTrackingClient)
        assert judge.stage == "judge"
        assert judge.config.model == "m1"
        strategy_client = env["strategy"].call_args.args[2]
        assert isinstance(strategy_client, UsageTrackingClient)
        assert strategy_client.stage == "strategy"
        detector_config = config["detector_config"]
        [member] = detector_config.judge_clients.values()
        assert isinstance(member, UsageTrackingClient)
        assert member.stage == "ensemble"
        assert isinstance(detector_config.prefilter_client, UsageTrackingClient)
        assert detector_config.prefilter_client.stage == "prefilter"
        out = _flat(result.output)
        for model in ("m1", "m2", "cheap"):
            warning = f"no price for model '{model}': its calls do not count towards --max-cost"
            assert out.count(warning) == 1

    def test_no_flags(self, runner: CliRunner, env: dict[str, Any]) -> None:
        result = self._scan(runner)
        assert result.exit_code == 0, result.output
        config = env["scanner"].call_args.kwargs["config"]
        assert config["max_campaign_tokens"] is None
        assert config["max_cost"] is None
        assert "llm_client" not in config
        assert env["strategy"].call_args.args[2] is None
        assert "Budget" not in result.output
        assert "no price for model" not in result.output

    @pytest.mark.parametrize(
        "flag", [("--max-campaign-tokens", "0"), ("--max-cost", "0"), ("--max-cost", "-1")]
    )
    def test_invalid_limits_exit_2(
        self, runner: CliRunner, env: dict[str, Any], flag: tuple[str, str]
    ) -> None:
        assert self._scan(runner, *flag).exit_code == 2

    def test_cost_cap_without_llm_warns(self, runner: CliRunner, env: dict[str, Any]) -> None:
        result = self._scan(runner, "--max-cost", "1")
        assert result.exit_code == 0, result.output
        assert "--max-cost cannot trigger: no LLM client is configured" in _flat(result.output)

    def test_priced_model_no_warning(self, runner: CliRunner, env: dict[str, Any]) -> None:
        Path(".ziran").mkdir()
        Path(".ziran/prices.yaml").write_text(
            "models:\n  m1: {input_per_mtok: 1, output_per_mtok: 2}\n", encoding="utf-8"
        )
        result = self._scan(runner, "--llm-model", "m1", "--max-cost", "1")
        assert result.exit_code == 0, result.output
        assert "no price for model" not in result.output
        ledger = env["scanner"].call_args.kwargs["config"]["usage_ledger"]
        assert ledger.prices.price_for("m1") is not None

    def test_invalid_price_table_exit_1(self, runner: CliRunner, env: dict[str, Any]) -> None:
        Path(".ziran").mkdir()
        Path(".ziran/prices.yaml").write_text("models: {m: {bogus: 1}}\n", encoding="utf-8")
        result = self._scan(runner)
        assert result.exit_code == 1
        assert "invalid price table" in result.output
        env["scanner"].assert_not_called()

    def test_budget_exceeded_status_and_hint(self, runner: CliRunner, env: dict[str, Any]) -> None:
        from ziran.domain.entities.phase import CampaignResult

        data = _minimal_campaign_result()
        data["metadata"] = {"status": "budget_exceeded"}
        env["asyncio"].run.return_value = CampaignResult.model_validate(data)
        result = self._scan(runner, "--max-campaign-tokens", "10")
        assert result.exit_code == 0, result.output
        out = _flat(result.output)
        assert "BUDGET EXCEEDED (partial results)" in out
        assert (
            "Budget reached; checkpoint kept in out. Re-run with --resume and a higher cap "
            "to continue." in out
        )


@pytest.mark.unit
class TestDisplayUsage:
    """Usage rows in the campaign summary (spec 047 US1.3, US1.4)."""

    _USAGE: ClassVar[dict[str, Any]] = {
        "currency": "USD",
        "entries": [
            {
                "stage": "judge",
                "model": "m",
                "calls": 1,
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "estimated_calls": 0,
                "cost_usd": 0.0123,
            },
            {
                "stage": "target",
                "model": "unknown",
                "calls": 1,
                "prompt_tokens": 1000,
                "completion_tokens": 234,
                "total_tokens": 1234,
                "estimated_calls": 0,
                "cost_usd": None,
            },
        ],
        "total_tokens": 1354,
        "total_cost_usd": 0.0123,
        "unpriced_tokens": 1234,
        "max_campaign_tokens": None,
        "max_cost_usd": None,
    }

    @staticmethod
    def _render(metadata: dict[str, Any]) -> str:
        from rich.console import Console

        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli import main

        data = _minimal_campaign_result()
        data["metadata"] = metadata
        console = Console(record=True, width=200)
        with patch.object(main, "console", console):
            main._display_results(CampaignResult.model_validate(data))
        return console.export_text()

    def test_rows_present(self) -> None:
        out = self._render({"usage": self._USAGE})
        assert "Usage · judge · m" in out
        assert "120 tokens · $0.0123" in out
        assert "Usage · target · unknown" in out
        assert "1,234 tokens · cost n/a" in out
        assert "All-Stage Tokens" in out
        assert "1,354" in out
        assert "$0.0123 (1,234 tokens unpriced)" in out
        assert "BUDGET EXCEEDED" not in out

    def test_rows_absent_without_usage(self) -> None:
        out = self._render({})
        for text in ("Usage ·", "All-Stage Tokens", "Estimated Cost", "BUDGET EXCEEDED"):
            assert text not in out

    def test_json_dump_carries_usage(self) -> None:
        from ziran.domain.entities.phase import CampaignResult
        from ziran.interfaces.cli.reports import _dump_campaign_result

        data = _minimal_campaign_result()
        data["metadata"] = {"usage": self._USAGE}
        dumped = _dump_campaign_result(CampaignResult.model_validate(data))
        assert dumped["metadata"]["usage"] == self._USAGE


@pytest.mark.unit
class TestLangGraphFramework:
    """Spec 050: ``--framework langgraph`` wiring."""

    @pytest.mark.parametrize("command", ["scan", "discover"])
    def test_choice_offered(self, command: str) -> None:
        param = next(p for p in cli.commands[command].params if p.name == "framework")
        assert "langgraph" in param.type.choices  # type: ignore[attr-defined]

    def test_init_offers_langgraph(self) -> None:
        from ziran.interfaces.cli import init_command

        assert "langgraph" in init_command._FRAMEWORKS

    def test_discover_lists_graph_tools(self, tmp_path: Path) -> None:
        pytest.importorskip("langgraph")
        agent = tmp_path / "my_graph.py"
        agent.write_text(
            "from tests.unit.test_langgraph_adapter import exfil_graph\ngraph = exfil_graph()\n"
        )
        result = CliRunner().invoke(cli, ["discover", "--framework", "langgraph", str(agent)])
        assert result.exit_code == 0, result.output
        assert "tool_read_file" in result.output
        assert "tool_http_request" in result.output
