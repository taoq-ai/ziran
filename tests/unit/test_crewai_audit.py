"""Tests for the CrewAI audit use case (spec 056)."""

from __future__ import annotations

import pytest

from ziran.application.static_analysis import crewai_audit
from ziran.application.static_analysis.crewai_audit import audit_crewai
from ziran.domain.entities.crewai import CrewAIAgent, CrewAIIssue, CrewAIScan, CrewAITask


def _unit(name: str, agent_tools: list[str], task_tools: list[str] | None = None) -> CrewAIAgent:
    tasks = [CrewAITask(name="t", tools=task_tools)] if task_tools else []
    return CrewAIAgent(
        name=name, file="cfg/agents.yaml", line=4, agent_tools=agent_tools, tasks=tasks
    )


@pytest.mark.unit
class TestAuditCrewAI:
    def test_chain_over_union_of_agent_and_task_tools(self) -> None:
        scan = CrewAIScan(root=".", agents=[_unit("researcher", ["FileReadTool"], ["send_email"])])
        [f] = audit_crewai(scan).findings
        assert (f.check_id, f.severity, f.file_path, f.line_number) == (
            "CR001",
            "critical",
            "cfg/agents.yaml",
            4,
        )
        assert (f.agent, f.tools) == ("researcher", ("FileReadTool", "send_email"))
        assert f.message == ("Agent 'researcher': data_exfiltration via FileReadTool -> send_email")
        assert f.recommendation

    def test_clean_and_empty_units(self) -> None:
        scan = CrewAIScan(
            root=".",
            agents=[_unit("a", ["SerperDevTool", "ScrapeWebsiteTool"]), _unit("b", [])],
            files_analyzed=2,
        )
        report = audit_crewai(scan)
        assert report.findings == []
        assert report.files_analyzed == 2

    def test_issues_and_errors_then_chains(self) -> None:
        unit = _unit("researcher", ["FileReadTool", "send_email"])
        unit.errors = [CrewAIIssue(file="crew.py", line=9, message="invalid Python syntax")]
        scan = CrewAIScan(
            root=".",
            agents=[unit],
            issues=[CrewAIIssue(file="other/agents.yaml", message="agents.yaml must be a mapping")],
        )
        findings = audit_crewai(scan).findings
        assert [(f.check_id, f.agent, f.file_path, f.line_number) for f in findings] == [
            ("CR000", None, "other/agents.yaml", None),
            ("CR000", "researcher", "crew.py", 9),
            ("CR001", "researcher", "cfg/agents.yaml", 4),
        ]
        assert all(f.severity == "high" for f in findings[:2])
        assert findings[1].message == "invalid Python syntax"

    def test_unit_over_tool_bound_gets_cr000_and_no_chains(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(crewai_audit, "MAX_UNIT_TOOLS", 2)
        within = _unit("within", ["FileReadTool"], ["send_email"])
        over = _unit("over", ["FileReadTool", "send_email"], ["SerperDevTool"])
        findings = audit_crewai(CrewAIScan(root=".", agents=[within, over])).findings
        assert [(f.check_id, f.agent) for f in findings] == [
            ("CR001", "within"),
            ("CR000", "over"),
        ]
        assert (findings[1].file_path, findings[1].line_number) == ("cfg/agents.yaml", 4)
        assert findings[1].message == "agent has more than 2 tools; chains not built"
