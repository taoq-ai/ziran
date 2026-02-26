"""Tests for the ReportGenerator — JSON, Markdown, HTML output."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

# ── helpers ──────────────────────────────────────────────────────────

def _campaign_data(*, vulnerable: bool = False) -> dict[str, Any]:
    base: dict[str, Any] = {
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
    if vulnerable:
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
        base["phases_executed"][0]["vulnerabilities_found"] = ["vuln_1"]
        base["phases_executed"][0]["success"] = True
        base["phases_executed"][0]["artifacts"] = {
            "vuln_1": {
                "name": "Prompt Injection",
                "severity": "critical",
                "category": "injection",
                "owasp_mapping": ["LLM01"],
            },
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
                "owasp_mapping": ["LLM01"],
            }
        ]
        base["token_usage"] = {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
    return base


def _make_result(*, vulnerable: bool = False):
    from ziran.domain.entities.phase import CampaignResult

    return CampaignResult.model_validate(_campaign_data(vulnerable=vulnerable))


# ── Tests ────────────────────────────────────────────────────────────

class TestReportGenerator:
    def test_save_json(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        out = gen.save_json(result)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["campaign_id"] == "test_campaign_001"

    def test_save_markdown_clean(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        out = gen.save_markdown(result)
        assert out.exists()
        content = out.read_text()
        assert "# ZIRAN Security Scan Report" in content
        assert "✅ PASSED" in content

    def test_save_markdown_vulnerable(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result(vulnerable=True)
        out = gen.save_markdown(result)
        content = out.read_text()
        assert "⚠️ VULNERABLE" in content
        assert "Prompt Injection" in content
        assert "Token Usage" in content
        assert "Dangerous Tool Chains" in content
        assert "Remediation Guidance" in content
        assert "OWASP LLM Top 10 Compliance" in content

    def test_save_html(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        with patch("ziran.interfaces.cli.html_report.build_html_report", return_value="<html></html>") as m:
            out = gen.save_html(result)
        assert out.exists()
        assert out.read_text() == "<html></html>"
        m.assert_called_once()

    def test_save_html_with_graph_state(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        gs = {"nodes": [{"id": "a"}], "edges": [], "stats": {}}
        with patch("ziran.interfaces.cli.html_report.build_html_report", return_value="<html/>"):
            out = gen.save_html(result, graph_state=gs)
        assert out.exists()

    def test_save_html_uses_phase_graph_state(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        # Inject a graph_state into the phase
        result.phases_executed[0].graph_state = {"nodes": [{"id": "x"}], "edges": [], "stats": {}}
        with patch("ziran.interfaces.cli.html_report.build_html_report", return_value="<html/>") as m:
            gen.save_html(result)
        m.assert_called_once()

    def test_output_dir_created(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "sub" / "dir"
        ReportGenerator(output_dir=new_dir)
        assert new_dir.exists()

    def test_markdown_phase_error(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result()
        result.phases_executed[0].error = "Something went wrong"
        out = gen.save_markdown(result)
        content = out.read_text()
        assert "Something went wrong" in content

    def test_markdown_many_critical_paths(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        result = _make_result(vulnerable=True)
        # Add more than 10 critical paths to test truncation
        result.critical_paths = [["a", "b"]] * 15
        out = gen.save_markdown(result)
        content = out.read_text()
        assert "...and 5 more paths" in content
