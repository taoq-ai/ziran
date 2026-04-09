"""Integration test for the analyze-traces CLI command."""

from __future__ import annotations

import json
from pathlib import Path

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
        assert result.exit_code == 0, result.output

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
        assert result.exit_code == 0, result.output

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
        assert result.exit_code == 0, result.output

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
        assert result.exit_code != 0

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
        assert result.exit_code == 0, result.output

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
        assert result.exit_code == 0, result.output

        data = json.loads((tmp_path / "trace_analysis.json").read_text())
        chains = data["dangerous_tool_chains"]
        # At least one chain should be found
        assert len(chains) > 0
        # Verify trace metadata is present
        for chain in chains:
            assert chain["observed_in_production"] is True
