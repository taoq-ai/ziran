"""Tests for HTML report generation and vis-network graph conversion."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from koan.domain.entities.phase import CampaignResult, PhaseResult, RomanceScanPhase
from koan.interfaces.cli.html_report import (
    _build_node_tooltip,
    _build_paths_html,
    _build_phases_html,
    _build_vulns_html,
    build_html_report,
    graph_state_to_vis,
)
from koan.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture()
def sample_graph_state() -> dict[str, Any]:
    """Minimal but representative graph state dict."""
    return {
        "nodes": [
            {"id": "cap_search", "node_type": "capability", "name": "Search Tool"},
            {"id": "tool_email", "node_type": "tool", "name": "send_email", "dangerous": True},
            {
                "id": "vuln_1",
                "node_type": "vulnerability",
                "name": "Prompt Injection",
                "severity": "high",
                "category": "injection",
            },
            {"id": "data_db", "node_type": "data_source", "name": "User DB"},
            {"id": "phase_recon", "node_type": "phase", "name": "Reconnaissance"},
            {"id": "agent_init", "node_type": "agent_state", "name": "Initial State"},
        ],
        "edges": [
            {"source": "cap_search", "target": "tool_email", "edge_type": "enables"},
            {"source": "tool_email", "target": "data_db", "edge_type": "accesses_data"},
            {"source": "vuln_1", "target": "phase_recon", "edge_type": "discovered_in"},
            {"source": "cap_search", "target": "vuln_1", "edge_type": "exploits"},
        ],
        "campaign_start": "2025-01-01T00:00:00+00:00",
        "campaign_duration_seconds": 42.0,
        "stats": {
            "total_nodes": 6,
            "total_edges": 4,
            "density": 0.133,
            "node_types": {
                "capability": 1,
                "tool": 1,
                "vulnerability": 1,
                "data_source": 1,
                "phase": 1,
                "agent_state": 1,
            },
        },
    }


@pytest.fixture()
def sample_campaign_result() -> CampaignResult:
    """Minimal campaign result for report tests."""
    return CampaignResult(
        campaign_id="test_campaign_001",
        target_agent="test-agent",
        phases_executed=[
            PhaseResult(
                phase=RomanceScanPhase.RECONNAISSANCE,
                success=True,
                trust_score=0.3,
                duration_seconds=5.0,
                vulnerabilities_found=["vuln_1"],
                artifacts={
                    "vuln_1": {
                        "name": "Prompt Injection",
                        "severity": "high",
                        "category": "injection",
                    }
                },
                graph_state={
                    "nodes": [{"id": "n1", "node_type": "capability", "name": "n1"}],
                    "edges": [],
                    "stats": {"total_nodes": 1, "total_edges": 0, "density": 0},
                },
            ),
            PhaseResult(
                phase=RomanceScanPhase.TRUST_BUILDING,
                success=True,
                trust_score=0.6,
                duration_seconds=3.0,
            ),
        ],
        total_vulnerabilities=1,
        critical_paths=[["cap_search", "tool_email", "data_db"]],
        final_trust_score=0.6,
        success=True,
    )


# ── graph_state_to_vis ─────────────────────────────────────────────────


class TestGraphStateToVis:
    def test_converts_nodes(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        assert len(vis["nodes"]) == 6
        ids = {n["id"] for n in vis["nodes"]}
        assert "cap_search" in ids
        assert "vuln_1" in ids

    def test_node_has_vis_properties(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        cap_node = next(n for n in vis["nodes"] if n["id"] == "cap_search")
        assert cap_node["shape"] == "dot"
        assert "color" in cap_node
        assert cap_node["nodeType"] == "capability"

    def test_vulnerability_has_shadow(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        vuln = next(n for n in vis["nodes"] if n["id"] == "vuln_1")
        assert vuln["borderWidth"] == 3
        assert vuln["shadow"]["enabled"] is True

    def test_converts_edges(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        assert len(vis["edges"]) == 4

    def test_edge_has_vis_properties(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        enables_edge = next(e for e in vis["edges"] if e["edgeType"] == "enables")
        assert enables_edge["from"] == "cap_search"
        assert enables_edge["to"] == "tool_email"
        assert enables_edge["arrows"] == "to"
        assert enables_edge["dashes"] is True

    def test_non_dashed_edge(self, sample_graph_state: dict[str, Any]) -> None:
        vis = graph_state_to_vis(sample_graph_state)
        access_edge = next(e for e in vis["edges"] if e["edgeType"] == "accesses_data")
        assert "dashes" not in access_edge

    def test_empty_graph(self) -> None:
        vis = graph_state_to_vis({"nodes": [], "edges": []})
        assert vis == {"nodes": [], "edges": []}

    def test_truncates_long_labels(self) -> None:
        state = {
            "nodes": [{"id": "x", "node_type": "tool", "name": "A" * 50}],
            "edges": [],
        }
        vis = graph_state_to_vis(state)
        assert len(vis["nodes"][0]["label"]) == 28  # 27 chars + "…"


# ── Node tooltip ───────────────────────────────────────────────────────


class TestBuildNodeTooltip:
    def test_includes_name(self) -> None:
        tip = _build_node_tooltip({"id": "n1", "name": "My Node"})
        assert "My Node" in tip

    def test_includes_risk_score(self) -> None:
        tip = _build_node_tooltip({"id": "n1", "name": "n1", "risk_score": 0.85})
        assert "0.85" in tip

    def test_includes_dangerous_marker(self) -> None:
        tip = _build_node_tooltip({"id": "n1", "name": "n1", "dangerous": True})
        assert "⚠️" in tip

    def test_truncates_description(self) -> None:
        tip = _build_node_tooltip({"id": "n1", "name": "n1", "description": "X" * 200})
        assert len(tip) < 300


# ── HTML fragment builders ─────────────────────────────────────────────


class TestBuildPhasesHtml:
    def test_renders_phases(self) -> None:
        phases = [
            {
                "phase": "reconnaissance",
                "trust_score": 0.3,
                "duration_seconds": 5.0,
                "vulnerabilities_found": ["v1"],
            },
            {
                "phase": "trust_building",
                "trust_score": 0.6,
                "duration_seconds": 3.0,
                "vulnerabilities_found": [],
            },
        ]
        html = _build_phases_html(phases)
        assert "Reconnaissance" in html
        assert "Trust Building" in html
        assert "phase-danger" in html
        assert "phase-ok" in html


class TestBuildPathsHtml:
    def test_renders_paths(self) -> None:
        paths = [["a", "b", "c"], ["x", "y"]]
        html = _build_paths_html(paths)
        assert "a → b → c" in html
        assert "#1" in html
        assert "#2" in html

    def test_empty_paths(self) -> None:
        html = _build_paths_html([])
        assert "No critical attack paths" in html


class TestBuildVulnsHtml:
    def test_renders_vulns(self) -> None:
        phases = [
            {
                "phase": "reconnaissance",
                "vulnerabilities_found": ["v1"],
                "artifacts": {
                    "v1": {"name": "SQL Injection", "severity": "critical", "category": "injection"}
                },
            }
        ]
        html = _build_vulns_html(phases)
        assert "SQL Injection" in html
        assert "sev-critical" in html

    def test_no_vulns(self) -> None:
        html = _build_vulns_html([{"phase": "recon", "vulnerabilities_found": [], "artifacts": {}}])
        assert "No vulnerabilities" in html


# ── Full HTML report ───────────────────────────────────────────────────


class TestBuildHtmlReport:
    def test_produces_valid_html(
        self,
        sample_campaign_result: CampaignResult,
        sample_graph_state: dict[str, Any],
    ) -> None:
        result_data = sample_campaign_result.model_dump(mode="json")
        html = build_html_report(result_data, sample_graph_state)

        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "vis-network" in html
        assert "test_campaign_001" in html

    def test_contains_graph_data(
        self,
        sample_campaign_result: CampaignResult,
        sample_graph_state: dict[str, Any],
    ) -> None:
        result_data = sample_campaign_result.model_dump(mode="json")
        html = build_html_report(result_data, sample_graph_state)

        assert "cap_search" in html
        assert "vuln_1" in html

    def test_contains_campaign_metrics(
        self,
        sample_campaign_result: CampaignResult,
        sample_graph_state: dict[str, Any],
    ) -> None:
        result_data = sample_campaign_result.model_dump(mode="json")
        html = build_html_report(result_data, sample_graph_state)

        assert "VULNERABLE" in html
        assert "0.60" in html  # trust score


# ── ReportGenerator.save_html ──────────────────────────────────────────


class TestReportGeneratorSaveHtml:
    def test_saves_html_file(
        self,
        tmp_path: Path,
        sample_campaign_result: CampaignResult,
        sample_graph_state: dict[str, Any],
    ) -> None:
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_html(sample_campaign_result, graph_state=sample_graph_state)

        assert path.exists()
        assert path.suffix == ".html"
        assert path.name == "test_campaign_001_report.html"

        content = path.read_text()
        assert "vis-network" in content
        assert "test_campaign_001" in content

    def test_falls_back_to_phase_graph_state(
        self,
        tmp_path: Path,
        sample_campaign_result: CampaignResult,
    ) -> None:
        """When no explicit graph_state is given, use the last phase's snapshot."""
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_html(sample_campaign_result)

        assert path.exists()
        content = path.read_text()
        # The fallback graph state from the fixture has node "n1"
        assert "n1" in content

    def test_empty_graph_state_fallback(self, tmp_path: Path) -> None:
        """Gracefully handles no graph state at all."""
        result = CampaignResult(
            campaign_id="empty_001",
            target_agent="agent",
            phases_executed=[
                PhaseResult(
                    phase=RomanceScanPhase.RECONNAISSANCE,
                    success=True,
                    trust_score=0.5,
                    duration_seconds=1.0,
                ),
            ],
            total_vulnerabilities=0,
            final_trust_score=0.5,
            success=False,
        )
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.save_html(result)
        assert path.exists()
        assert path.read_text().startswith("<!DOCTYPE html>")
