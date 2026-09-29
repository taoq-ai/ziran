"""Tests for the Claude Code audit use case (spec 038)."""

from __future__ import annotations

import time

import pytest

from ziran.application.static_analysis.analyzer import StaticFinding
from ziran.application.static_analysis.claude_code_audit import agent_chains, audit_claude_code
from ziran.application.static_analysis.config import (
    CheckDefinition,
    PatternRule,
    StaticAnalysisConfig,
)
from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent,
    ClaudeCodeParseIssue,
    ClaudeCodeScan,
)

SECRET = "ziran-fake-secret-0418"


def _agent(
    name: str = "researcher",
    tools: str | None = None,
    *,
    description: str = "",
    system_prompt: str = "",
) -> ClaudeCodeAgent:
    key_lines = {"name": 2, "description": 3}
    if tools is not None:
        key_lines["tools"] = 4
    return ClaudeCodeAgent(
        name=name,
        tools=tools,
        description=description,
        file=f"agents/{name}.md",
        key_lines=key_lines,
        system_prompt=system_prompt,
        body_line=7,
    )


def _scan(
    *agents: ClaudeCodeAgent, issues: list[ClaudeCodeParseIssue] | None = None
) -> ClaudeCodeScan:
    return ClaudeCodeScan(root=".", agents=list(agents), issues=issues or [], files_analyzed=3)


def _rules(findings: list[StaticFinding], rule: str) -> list[StaticFinding]:
    return [f for f in findings if f.check_id == rule]


@pytest.mark.unit
class TestStaticFindingFields:
    def test_defaults(self) -> None:
        f = StaticFinding(check_id="X", message="m", severity="low", file_path="f")
        assert f.agent is None
        assert f.tools == ()

    def test_explicit(self) -> None:
        f = StaticFinding(
            check_id="X", message="m", severity="low", file_path="f", agent="a", tools=("Read",)
        )
        assert f.agent == "a"
        assert f.tools == ("Read",)


@pytest.mark.unit
class TestAgentChains:
    def test_researcher_direct_exfiltration(self) -> None:
        chains = agent_chains(_agent(tools="Read, Grep, WebFetch, mcp__slack__send_message"))
        assert sorted(c.tools for c in chains) == sorted(
            [
                ["Read", "WebFetch"],
                ["Read", "mcp__slack__send_message"],
                ["Grep", "WebFetch"],
                ["Grep", "mcp__slack__send_message"],
            ]
        )
        assert all(c.risk_level == "critical" for c in chains)
        assert all(c.vulnerability_type == "data_exfiltration" for c in chains)
        assert all(c.chain_type != "cycle" for c in chains)

    @pytest.mark.parametrize("tools", ["Read, Grep, Glob", "Read"])
    def test_read_only_has_no_chain(self, tools: str) -> None:
        assert agent_chains(_agent(tools=tools)) == []

    def test_bare_bash(self) -> None:
        chains = agent_chains(_agent(tools="Bash"))
        assert len(chains) == 1
        assert chains[0].tools == ["Bash"]
        assert chains[0].vulnerability_type == "unrestricted_execution"
        assert chains[0].risk_level == "high"

    def test_unrestricted_is_fast(self) -> None:
        start = time.monotonic()
        chains = agent_chains(_agent(name="generalist"))
        assert time.monotonic() - start < 1
        tools = [c.tools for c in chains]
        assert ["Bash"] in tools
        read_fetch = next(c for c in chains if c.tools == ["Read", "WebFetch"])
        assert read_fetch.risk_level == "critical"


@pytest.mark.unit
class TestAuditClaudeCode:
    def test_sa007_unrestricted(self) -> None:
        report = audit_claude_code(_scan(_agent(name="generalist")))
        [sa007] = _rules(report.findings, "SA007")
        assert sa007.severity == "high"
        assert sa007.line_number == 1
        assert sa007.agent == "generalist"
        assert sa007.tools == ()
        assert sa007.message == "Agent 'generalist' has no 'tools' key and inherits every tool"
        assert _rules(report.findings, "SA003") == []

    def test_sa003_dangerous_declared_tools(self) -> None:
        report = audit_claude_code(_scan(_agent(tools="Read, WebFetch, mcp__slack__send_message")))
        sa003 = _rules(report.findings, "SA003")
        assert [f.tools for f in sa003] == [("WebFetch",), ("mcp__slack__send_message",)]
        assert all(f.severity == "high" and f.line_number == 4 for f in sa003)
        assert sa003[0].message == "Agent 'researcher' is granted dangerous tool 'WebFetch'"

    def test_sa003_none_for_read_only(self) -> None:
        report = audit_claude_code(_scan(_agent(tools="Read, Grep, Glob")))
        assert report.findings == []

    def test_sa004_wildcards(self) -> None:
        report = audit_claude_code(
            _scan(_agent(tools="Bash(*), mcp__github, mcp__slack__*, Bash(npm test:*)"))
        )
        sa004 = _rules(report.findings, "SA004")
        assert [f.tools for f in sa004] == [("Bash(*)",), ("mcp__github",), ("mcp__slack__*",)]
        assert all(f.severity == "medium" and f.line_number == 4 for f in sa004)
        assert sa004[0].message == "Agent 'researcher' is granted wildcard tool 'Bash(*)'"

    def test_sa001_body_and_description(self) -> None:
        agent = _agent(
            tools="Read",
            description=f'api_key: "{SECRET}"',
            system_prompt=f'Intro line.\napi_key = "{SECRET}"\n',
        )
        sa001 = _rules(audit_claude_code(_scan(agent)).findings, "SA001")
        assert [f.line_number for f in sa001] == [3, 8]
        assert all(f.severity == "critical" and f.agent == "researcher" for f in sa001)
        assert all(SECRET not in f.message for f in sa001)

    def test_sa001_custom_config(self) -> None:
        agent = _agent(tools="Read", system_prompt="ziran-custom-marker here")
        assert _rules(audit_claude_code(_scan(agent)).findings, "SA001") == []
        config = StaticAnalysisConfig.default().model_copy(
            update={
                "secret_checks": [
                    CheckDefinition(
                        check_id="SA001",
                        message="custom",
                        severity="critical",
                        patterns=[PatternRule(pattern="ziran-custom-marker")],
                    )
                ]
            }
        )
        [f] = _rules(audit_claude_code(_scan(agent), config).findings, "SA001")
        assert f.line_number == 7
        assert f.message == "custom"

    def test_cc001_mirrors_chains(self) -> None:
        agent = _agent(tools="Read, Grep, WebFetch, mcp__slack__send_message")
        cc001 = _rules(audit_claude_code(_scan(agent)).findings, "CC001")
        chains = agent_chains(agent)
        assert [(f.severity, f.tools) for f in cc001] == [
            (c.risk_level, tuple(c.tools)) for c in chains
        ]
        assert all(f.line_number == 4 and f.agent == "researcher" for f in cc001)
        assert "Agent 'researcher': data_exfiltration via Read -> WebFetch" in {
            f.message for f in cc001
        }
        assert len({(f.agent, f.tools) for f in cc001}) == len(cc001)

    def test_cc000_and_order(self) -> None:
        issue = ClaudeCodeParseIssue(file="agents/b.md", line=3, message="m")
        agent = _agent(name="generalist", system_prompt=f'api_key = "{SECRET}"', description="")
        report = audit_claude_code(_scan(agent, issues=[issue]))
        assert report.files_analyzed == 3
        first = report.findings[0]
        assert (first.check_id, first.severity, first.file_path, first.line_number) == (
            "CC000",
            "high",
            "agents/b.md",
            3,
        )
        assert first.agent is None
        assert first.message == "m"
        order = [f.check_id for f in report.findings]
        assert order[:3] == ["CC000", "SA001", "SA007"]
        assert set(order[3:]) == {"CC001"}
