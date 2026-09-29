"""Integration test for the analyze-traces CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
OTEL_FIXTURE = FIXTURES_DIR / "sample_otel_traces.jsonl"
LANGFUSE_FIXTURE = FIXTURES_DIR / "sample_langfuse_traces.json"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.integration
class TestAnalyzeTracesCLI:
    def test_otel_json_output(self, runner: CliRunner, tmp_path: Path) -> None:
        """Full round-trip: OTel fixture -> JSON report."""
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(OTEL_FIXTURE),
                "--out",
                str(tmp_path),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 1, result.output

        report = tmp_path / "trace_analysis.json"
        assert report.exists()

        data = json.loads(report.read_text())
        assert data["source"] == "trace-analysis"
        assert data["campaign_id"].startswith("trace-")
        assert isinstance(data["dangerous_tool_chains"], list)

    def test_otel_markdown_output(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(OTEL_FIXTURE),
                "--out",
                str(tmp_path),
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code == 1, result.output

        report = tmp_path / "trace_analysis.md"
        assert report.exists()
        content = report.read_text()
        assert "# Trace Analysis Report" in content

    def test_langfuse_file_mode(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "langfuse",
                "--input",
                str(LANGFUSE_FIXTURE),
                "--out",
                str(tmp_path),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 1, result.output

        report = tmp_path / "trace_analysis.json"
        assert report.exists()

    def test_otel_requires_input(self, runner: CliRunner, tmp_path: Path) -> None:
        """OTel source without --input should fail."""
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--out",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2

    def test_verbose_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(OTEL_FIXTURE),
                "--out",
                str(tmp_path),
                "-v",
            ],
        )
        assert result.exit_code == 1, result.output

    def test_finds_dangerous_chains_in_otel(self, runner: CliRunner, tmp_path: Path) -> None:
        """The OTel fixture contains read_file->http_request."""
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(OTEL_FIXTURE),
                "--out",
                str(tmp_path),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 1, result.output

        data = json.loads((tmp_path / "trace_analysis.json").read_text())
        chains = data["dangerous_tool_chains"]
        # At least one chain should be found
        assert len(chains) > 0
        # Verify trace metadata is present
        for chain in chains:
            assert chain["observed_in_production"] is True


# ── Claude Code span contract v1 (#421) ──────────────────────────────

CC_DIR = FIXTURES_DIR / "claude_code_traces"


def _run_otel(
    runner: CliRunner, input_path: Path, out: Path, fmt: str = "json"
) -> tuple[int, str, dict[str, Any]]:
    result = runner.invoke(
        cli,
        [
            "analyze-traces",
            "--source",
            "otel",
            "--input",
            str(input_path),
            "--out",
            str(out),
            "--format",
            fmt,
        ],
    )
    report = out / "trace_analysis.json"
    data: dict[str, Any] = json.loads(report.read_text()) if report.exists() else {}
    return result.exit_code, result.output, data


@pytest.mark.integration
class TestClaudeCodeTraces:
    def test_read_env_then_webfetch_is_critical(self, runner: CliRunner, tmp_path: Path) -> None:
        code, output, data = _run_otel(runner, CC_DIR / "read_env_then_webfetch.jsonl", tmp_path)
        assert code == 1, output
        chain = next(c for c in data["dangerous_tool_chains"] if c["tools"] == ["Read", "WebFetch"])
        assert chain["risk_level"] == "critical"
        assert chain["vulnerability_type"] == "data_exfiltration"
        assert isinstance(chain["risk_score"], float)
        assert chain["evidence"]["sessions"][0]["session_id"] == "cc-session-exfil"
        assert data["critical_chain_count"] >= 1
        assert data["metadata"]["sessions_analyzed"] == 1

    def test_read_then_grep_is_clean(self, runner: CliRunner, tmp_path: Path) -> None:
        code, output, data = _run_otel(runner, CC_DIR / "read_then_grep.jsonl", tmp_path)
        assert code == 0, output
        assert data["dangerous_tool_chains"] == []

    def test_two_sessions_not_merged(self, runner: CliRunner, tmp_path: Path) -> None:
        code, output, data = _run_otel(runner, CC_DIR / "two_sessions.jsonl", tmp_path)
        assert code == 0, output
        assert data["metadata"]["sessions_analyzed"] == 2
        assert data["dangerous_tool_chains"] == []

    def test_bash_secrets_never_written(self, runner: CliRunner, tmp_path: Path) -> None:
        out = tmp_path / "out"
        code, output, data = _run_otel(runner, CC_DIR / "bash_with_secret.jsonl", out)
        assert code == 0, output
        bash = next(c for c in data["dangerous_tool_chains"] if c["tools"] == ["Bash"])
        commands = bash["evidence"]["sessions"][0]["commands"]
        assert commands
        assert all("[REDACTED]" in cmd for cmd in commands)
        for secret in ("ziran-fake-token-0001", "ziran-fake-key-0002"):
            assert secret not in output
            for path in out.rglob("*"):
                if path.is_file():
                    assert secret not in path.read_text()

    def test_markdown_critical_exits_one(self, runner: CliRunner, tmp_path: Path) -> None:
        code, output, _ = _run_otel(
            runner, CC_DIR / "read_env_then_webfetch.jsonl", tmp_path, fmt="markdown"
        )
        assert code == 1, output

    @pytest.mark.parametrize("kind", ["missing", "directory", "garbage"])
    def test_unreadable_input_exits_two(self, runner: CliRunner, tmp_path: Path, kind: str) -> None:
        target = tmp_path / "input.jsonl"
        if kind == "directory":
            target.mkdir()
        elif kind == "garbage":
            target.write_text("not json\n")
        code, output, _ = _run_otel(runner, target, tmp_path / "out")
        assert code == 2, output
        assert "Error" in output
        assert "Traceback" not in output

    def test_alert_without_config_exits_two(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(CC_DIR / "read_then_grep.jsonl"),
                "--out",
                str(tmp_path),
                "--alert",
            ],
        )
        assert result.exit_code == 2, result.output
        assert "Error" in result.output
