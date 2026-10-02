"""Runs ``examples/25-claude-code-plugin`` offline (spec 044): safe passes, vulnerable fails."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.analyze_traces import analyze_traces
from ziran.interfaces.cli.main import cli
from ziran.interfaces.cli.watch_registry import watch_registry

EXAMPLE = Path(__file__).parents[2] / "examples" / "25-claude-code-plugin"
SAFE = EXAMPLE / "safe-plugin"
VULN = EXAMPLE / "vulnerable-plugin"


def _audit(*args: str) -> tuple[int, Any]:
    result = CliRunner().invoke(cli, ["audit", *args])
    return result.exit_code, result.stdout


@pytest.mark.integration
class TestClaudeCodePluginExample:
    def test_audit_safe_plugin_is_clean(self) -> None:
        code, out = _audit(str(SAFE), "--format", "json", "--severity", "low")
        assert code == 0
        assert json.loads(out)["findings"] == []
        assert _audit(str(SAFE))[0] == 0

    def test_audit_vulnerable_plugin_is_flagged(self) -> None:
        code, out = _audit(str(VULN), "--format", "json")
        assert code == 1
        rows = [
            r
            for r in json.loads(out)["findings"]
            if r["rule"] == "CC001" and r["tools"] == ["Read", "WebFetch"]
        ]
        assert rows
        assert rows[0]["severity"] == "critical"
        assert rows[0]["agent"] == "researcher"
        assert _audit(str(VULN))[0] == 1

    def test_traces(self, tmp_path: Path) -> None:
        def run(name: str) -> tuple[int, dict[str, Any]]:
            out = tmp_path / name
            trace = str(EXAMPLE / "traces" / f"{name}.jsonl")
            args = ["--source", "otel", "--input", trace, "--out", str(out)]
            result = CliRunner().invoke(analyze_traces, args)
            report = json.loads((out / "trace_analysis.json").read_text())
            return result.exit_code, report

        code, report = run("safe")
        assert code == 0
        assert report["critical_chain_count"] == 0
        code, report = run("vulnerable")
        assert code == 1
        assert any(
            c["tools"] == ["Read", "WebFetch"]
            and c["risk_level"] == "critical"
            and c["vulnerability_type"] == "data_exfiltration"
            for c in report["dangerous_tool_chains"]
        )

    def test_mcp_registry_import(self, tmp_path: Path) -> None:
        def run(plugin: Path, name: str) -> tuple[int, list[dict[str, Any]]]:
            out = tmp_path / name
            snap = str(tmp_path / f"{name}-snap")
            config = str(plugin / ".mcp.json")
            args = ["--from-claude-config", config, "--snapshot-dir", snap, "--out", str(out)]
            result = CliRunner().invoke(watch_registry, args)
            report = json.loads((out / "registry-watch-report.json").read_text())
            return result.exit_code, report

        assert run(SAFE, "safe") == (0, [])
        code, report = run(VULN, "vuln")
        assert code == 1
        assert any(
            r["drift_type"] == "tool_poisoning"
            and r["severity"] == "critical"
            and r["tool_name"] == "search_docs"
            for r in report
        )
