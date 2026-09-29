"""Tests for the Claude Code audit allowlist baseline (spec 039)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ziran.application.static_analysis.analyzer import StaticFinding
from ziran.application.static_analysis.claude_code_audit import agent_chains, audit_claude_code
from ziran.application.static_analysis.claude_code_baseline import (
    AuditBaseline,
    BaselineChain,
    BaselineNarrowing,
    apply_baseline,
    build_baseline,
)
from ziran.domain.entities.claude_code import ClaudeCodeAgent, ClaudeCodeScan

BUILDER_TOOLS = "Read, Glob, Grep, Bash, Write, Edit"
RESEARCHER_TOOLS = "Read, Grep, WebFetch, mcp__slack__send_message"


def _agent(name: str, tools: str | None) -> ClaudeCodeAgent:
    key_lines = {"name": 2, "description": 3}
    if tools is not None:
        key_lines["tools"] = 4
    return ClaudeCodeAgent(
        name=name,
        tools=tools,
        description=f"{name} description text",
        file=f"agents/{name}.md",
        key_lines=key_lines,
        system_prompt=f"{name} system prompt text",
        body_line=6,
    )


def _scan(*agents: ClaudeCodeAgent) -> ClaudeCodeScan:
    return ClaudeCodeScan(root=".", agents=list(agents), files_analyzed=len(agents))


def _apply(
    scan: ClaudeCodeScan, baseline: AuditBaseline
) -> tuple[list[StaticFinding], list[BaselineNarrowing]]:
    return apply_baseline(audit_claude_code(scan).findings, scan, baseline)


def _rules(findings: list[StaticFinding], prefix: str) -> list[StaticFinding]:
    return [f for f in findings if f.check_id.startswith(prefix)]


def _narrow(agent: str, change: str, tools: list[str] | None = None) -> BaselineNarrowing:
    return BaselineNarrowing(agent=agent, change=change, tools=tools or [])  # type: ignore[arg-type]


@pytest.mark.unit
class TestBuildBaseline:
    def test_agents_sorted_tools_verbatim_chains_sorted(self) -> None:
        scan = _scan(_agent("researcher", RESEARCHER_TOOLS), _agent("generalist", None))
        b = build_baseline(scan)
        assert b.version == 1
        assert list(b.agents) == ["generalist", "researcher"]
        r = b.agents["researcher"]
        assert r.tools == ["Read", "Grep", "WebFetch", "mcp__slack__send_message"]
        assert b.agents["generalist"].tools is None
        assert [c.tools for c in r.chains] == sorted(c.tools for c in r.chains)
        assert (
            BaselineChain(
                tools=["Read", "WebFetch"],
                vulnerability_type="data_exfiltration",
                severity="critical",
            )
            in r.chains
        )
        assert ["Bash"] in [c.tools for c in b.agents["generalist"].chains]

    def test_serialisation_deterministic_and_without_prompts(self) -> None:
        def build() -> str:
            scan = _scan(_agent("researcher", RESEARCHER_TOOLS), _agent("generalist", None))
            return build_baseline(scan).model_dump_json(indent=2)

        text = build()
        assert text == build()
        assert "system prompt text" not in text
        assert "description text" not in text

    @pytest.mark.parametrize(
        "doc",
        [
            '{"agents": {}}',
            '{"version": 2, "agents": {}}',
            '{"version": 1, "agents": {}, "extra": 1}',
            '{"version": 1, "agents": {"a": {"tools": null, "x": 1}}}',
            '{"version": 1, "agents": {"a": {"tools": "Read"}}}',
            '{"version": 1, "agents": {"a": {"tools": null, "chains": '
            '[{"tools": [], "vulnerability_type": "v", "severity": "s"}]}}}',
            '{"version": 1, "agents": {"a": {"chains": []}}}',
        ],
    )
    def test_rejects_invalid(self, doc: str) -> None:
        with pytest.raises(ValidationError):
            AuditBaseline.model_validate_json(doc)

    def test_accepts_minimal(self) -> None:
        assert AuditBaseline.model_validate_json('{"version": 1, "agents": {}}').agents == {}
        b = AuditBaseline.model_validate_json('{"version": 1, "agents": {"a": {"tools": null}}}')
        assert b.agents["a"].tools is None
        assert b.agents["a"].chains == []


@pytest.mark.unit
class TestApplyBaseline:
    def test_unchanged_scan_is_clean(self) -> None:
        scan = _scan(_agent("builder", BUILDER_TOOLS), _agent("generalist", None))
        findings, narrowed = _apply(scan, build_baseline(scan))
        rules = {f.check_id for f in findings}
        assert not rules & {"CC001", "SA003", "SA004", "SA007"}
        assert not _rules(findings, "BL")
        assert narrowed == []

    def test_wuwei_added_webfetch(self) -> None:
        baseline = build_baseline(_scan(_agent("builder", BUILDER_TOOLS)))
        scan = _scan(_agent("builder", BUILDER_TOOLS + ", WebFetch"))
        findings, narrowed = _apply(scan, baseline)
        bl001 = _rules(findings, "BL001")
        assert len(bl001) == 1
        f = bl001[0]
        assert f.tools == ("WebFetch",)
        assert f.message == "Agent 'builder' gains tool 'WebFetch' not in the baseline"
        assert (f.line_number, f.severity, f.agent) == (4, "critical", "builder")
        assert f.file_path == "agents/builder.md"
        bl003 = _rules(findings, "BL003")
        accepted = {tuple(c.tools) for c in baseline.agents["builder"].chains}
        expected = [tuple(c.tools) for c in agent_chains(scan.agents[0])]
        assert [f.tools for f in bl003] == [t for t in expected if t not in accepted]
        rw = next(f for f in bl003 if f.tools == ("Read", "WebFetch"))
        assert rw.message == (
            "Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch "
            "not in the baseline"
        )
        assert all(f.severity == "critical" for f in bl003)
        # Accepted grants and chains are gone; the new dangerous grant stays.
        sa003 = [f.tools for f in _rules(findings, "SA003")]
        assert sa003 == [("WebFetch",)]
        assert not _rules(findings, "CC001")
        # Order: kept findings, BL001, BL003.
        rules = [f.check_id for f in findings]
        assert rules == sorted(rules, key=lambda r: {"BL001": 1, "BL003": 2}.get(r, 0))
        assert narrowed == []

    def test_narrowing_tool_removed(self) -> None:
        baseline = build_baseline(_scan(_agent("researcher", RESEARCHER_TOOLS)))
        scan = _scan(_agent("researcher", "Read, Grep, mcp__slack__send_message"))
        findings, narrowed = _apply(scan, baseline)
        assert not _rules(findings, "BL")
        assert narrowed[0] == _narrow("researcher", "tool_removed", ["WebFetch"])
        removed = [n.tools for n in narrowed if n.change == "chain_removed"]
        assert ["Read", "WebFetch"] in removed
        assert ["Grep", "WebFetch"] in removed
        assert removed == [
            c.tools
            for c in baseline.agents["researcher"].chains
            if c.tools in removed  # baseline order
        ]

    def test_tools_key_lost(self) -> None:
        baseline = build_baseline(_scan(_agent("builder", BUILDER_TOOLS)))
        scan = _scan(_agent("builder", None))
        findings, _ = _apply(scan, baseline)
        bl002 = _rules(findings, "BL002")
        assert len(bl002) == 1
        assert bl002[0].tools == ()
        assert bl002[0].line_number == 1
        assert bl002[0].message == (
            "Agent 'builder' lost its 'tools' key and now inherits every tool"
        )
        assert not _rules(findings, "BL001")
        assert _rules(findings, "BL003")
        assert _rules(findings, "SA007")

    def test_tools_key_added(self) -> None:
        baseline = build_baseline(_scan(_agent("generalist", None)))
        scan = _scan(_agent("generalist", "Read"))
        findings, narrowed = _apply(scan, baseline)
        assert not _rules(findings, "BL")
        assert not _rules(findings, "SA007")
        assert _narrow("generalist", "tools_key_added") in narrowed

    def test_new_agent(self) -> None:
        baseline = build_baseline(_scan(_agent("builder", BUILDER_TOOLS)))
        scan = _scan(_agent("builder", BUILDER_TOOLS), _agent("helper", "Read"))
        findings, _ = _apply(scan, baseline)
        bl004 = _rules(findings, "BL004")
        assert [(f.agent, f.tools, f.message) for f in bl004] == [
            ("helper", ("Read",), "Agent 'helper' is not in the baseline")
        ]

    def test_agent_removed(self) -> None:
        baseline = build_baseline(_scan(_agent("builder", BUILDER_TOOLS), _agent("helper", "Read")))
        findings, narrowed = _apply(_scan(_agent("builder", BUILDER_TOOLS)), baseline)
        assert not _rules(findings, "BL")
        assert narrowed == [_narrow("helper", "agent_removed")]

    def test_chain_deleted_from_baseline(self) -> None:
        scan = _scan(_agent("builder", BUILDER_TOOLS))
        baseline = build_baseline(scan)
        dropped = baseline.agents["builder"].chains.pop(0)
        findings, _ = _apply(scan, baseline)
        assert [f.tools for f in _rules(findings, "BL")] == [tuple(dropped.tools)]
        assert _rules(findings, "BL")[0].check_id == "BL003"

    def test_cc000_escalated_others_unchanged_input_not_mutated(self) -> None:
        scan = _scan(_agent("builder", BUILDER_TOOLS))
        baseline = build_baseline(scan)
        cc000 = StaticFinding("CC000", "bad", "high", "agents/broken.md", 3)
        py = StaticFinding("SA001", "secret", "critical", "agent.py", 1)
        agent_sa001 = StaticFinding(
            "SA001", "secret", "critical", "agents/builder.md", 7, agent="builder"
        )
        findings = [cc000, py, agent_sa001]
        out, _ = apply_baseline(findings, scan, baseline)
        assert findings == [cc000, py, agent_sa001]
        assert cc000.severity == "high"
        assert out[0].check_id == "CC000"
        assert out[0].severity == "critical"
        assert out[1:] == [py, agent_sa001]

    def test_scoped_bash_is_a_widening(self) -> None:
        baseline = build_baseline(_scan(_agent("builder", "Read, Bash")))
        scan = _scan(_agent("builder", "Read, Bash(npm test:*)"))
        findings, narrowed = _apply(scan, baseline)
        assert [f.tools for f in _rules(findings, "BL001")] == [("Bash(npm test:*)",)]
        assert _narrow("builder", "tool_removed", ["Bash"]) in narrowed
