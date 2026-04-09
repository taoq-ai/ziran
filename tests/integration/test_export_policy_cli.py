"""Integration tests for the export-policy CLI command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli

# Inline fixture: minimal campaign result with dangerous tool chains
_CAMPAIGN_RESULT = {
    "campaign_id": "integ-test",
    "target_agent": "test-agent",
    "phases_executed": [],
    "total_vulnerabilities": 2,
    "final_trust_score": 0.3,
    "success": True,
    "dangerous_tool_chains": [
        {
            "tools": ["read_file", "http_request"],
            "risk_level": "critical",
            "vulnerability_type": "data_exfiltration",
            "exploit_description": "File read then exfil via HTTP",
        },
        {
            "tools": ["sql_query", "http_request"],
            "risk_level": "high",
            "vulnerability_type": "sql_to_rce",
            "exploit_description": "SQL data exfil",
        },
        {
            "tools": ["read_file", "encode", "http_request"],
            "risk_level": "medium",
            "vulnerability_type": "data_exfiltration",
            "exploit_description": "Encoded data exfil",
        },
    ],
}


@pytest.fixture
def result_file(tmp_path: Path) -> Path:
    """Write the inline campaign result to a temp JSON file."""
    path = tmp_path / "result.json"
    path.write_text(
        json.dumps(_CAMPAIGN_RESULT),
        encoding="utf-8",
    )
    return path


@pytest.mark.integration
class TestExportPolicyCli:
    def test_rego_export(
        self,
        result_file: Path,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(result_file),
                "--format",
                "rego",
                "--out",
                str(out_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        rego_files = list(out_dir.glob("*.rego"))
        assert len(rego_files) >= 1

        # Verify content of first file
        content = rego_files[0].read_text(encoding="utf-8")
        assert "package ziran.guardrails" in content

    def test_cedar_export_skips_three_tool_chain(
        self,
        result_file: Path,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(result_file),
                "--format",
                "cedar",
                "--out",
                str(out_dir),
                "--severity-floor",
                "medium",
                "--verbose",
            ],
        )

        assert result.exit_code == 0, result.output
        cedar_files = list(out_dir.glob("*.cedar"))
        # 3 chains but the 3-tool one is skipped
        assert len(cedar_files) == 2
        assert "skipped" in result.output.lower()

    def test_nemo_export(
        self,
        result_file: Path,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(result_file),
                "--format",
                "nemo",
                "--out",
                str(out_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        co_files = list(out_dir.glob("*.co"))
        assert len(co_files) >= 1

    def test_invariant_export(
        self,
        result_file: Path,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(result_file),
                "--format",
                "invariant",
                "--out",
                str(out_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        inv_files = list(out_dir.glob("*.invariant"))
        assert len(inv_files) >= 1

    def test_severity_floor_filters(
        self,
        result_file: Path,
        tmp_path: Path,
    ) -> None:
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(result_file),
                "--format",
                "rego",
                "--out",
                str(out_dir),
                "--severity-floor",
                "critical",
            ],
        )

        assert result.exit_code == 0, result.output
        rego_files = list(out_dir.glob("*.rego"))
        # Only the critical chain should be exported
        assert len(rego_files) == 1

    def test_empty_chains_prints_message(
        self,
        tmp_path: Path,
    ) -> None:
        empty_result = {
            "campaign_id": "empty",
            "target_agent": "test",
            "phases_executed": [],
            "total_vulnerabilities": 0,
            "final_trust_score": 1.0,
            "success": False,
            "dangerous_tool_chains": [],
        }
        path = tmp_path / "empty.json"
        path.write_text(
            json.dumps(empty_result),
            encoding="utf-8",
        )
        out_dir = tmp_path / "policies"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "export-policy",
                "--result",
                str(path),
                "--format",
                "rego",
                "--out",
                str(out_dir),
            ],
        )

        assert result.exit_code == 0
        assert "nothing exported" in result.output.lower()
