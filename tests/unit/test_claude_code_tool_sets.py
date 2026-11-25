"""Unit tests: inherited tool sets, egress and `tools` shapes (spec 099, changes 2, 4 and 6 with A6)."""

from __future__ import annotations

import timeit
from typing import TYPE_CHECKING

import pytest

from ziran.application.knowledge_graph.role_typing import tool_roles
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.application.static_analysis.claude_code_audit import (
    agent_chains,
    audit_claude_code,
    declared_tools,
)
from ziran.application.static_analysis.claude_code_baseline import apply_baseline, build_baseline
from ziran.infrastructure.config.claude_code_plugin import _split_tools, load_claude_code

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.claude_code import ClaudeCodeAgent, ClaudeCodeScan

pytestmark = pytest.mark.unit
LT = "lethal_trifecta"  # spec 088: one more chain over the same tools


def _load(tmp_path: Path, frontmatter: str) -> ClaudeCodeScan:
    file = tmp_path / "agents" / "helper.md"
    file.parent.mkdir(exist_ok=True)
    file.write_text(f"---\nname: helper\ndescription: d\n{frontmatter}---\nYou help.\n")
    scan = load_claude_code(tmp_path)
    assert scan.issues == []
    return scan


def _agent(tmp_path: Path, frontmatter: str) -> ClaudeCodeAgent:
    (agent,) = _load(tmp_path, frontmatter).agents
    return agent


def _rules(scan: ClaudeCodeScan) -> list[str]:
    return [f.check_id for f in audit_claude_code(scan, typed=True).findings]


# ── Change 2: no chain finding from an inherited tool set ────────────


def test_an_agent_with_no_tools_key_gets_sa007_and_no_chain(tmp_path: Path) -> None:
    scan = _load(tmp_path, "")
    assert declared_tools(scan.agents[0]) is None
    assert agent_chains(scan.agents[0], typed=True) == []
    assert _rules(scan) == ["SA007"]


def test_an_agent_with_a_declared_list_gives_its_chains(tmp_path: Path) -> None:
    scan = _load(tmp_path, "tools: Read, WebFetch\n")
    chains = agent_chains(scan.agents[0])
    assert [(c.tools, c.vulnerability_type) for c in chains if c.vulnerability_type != LT] == [
        (["Read", "WebFetch"], "data_exfiltration")
    ]
    assert "CC001" in _rules(scan) and "SA007" not in _rules(scan)


def test_the_baseline_of_an_inherited_set_holds_no_chain(tmp_path: Path) -> None:
    scan = _load(tmp_path, "")
    baseline = build_baseline(scan)
    assert baseline.agents["helper"].tools is None and baseline.agents["helper"].chains == []
    kept, _ = apply_baseline(audit_claude_code(scan).findings, scan, baseline)
    assert kept == []


# ── Change 6 (A6): every `tools` shape is read ───────────────────────


def test_a_space_list_is_several_tools(tmp_path: Path) -> None:
    assert _agent(tmp_path, "tools: Read Grep Bash\n").tools == ["Read", "Grep", "Bash"]


def test_a_space_inside_a_specifier_is_kept(tmp_path: Path) -> None:
    agent = _agent(tmp_path, "tools: Read Bash(git status:*), Grep\n")
    assert agent.tools == ["Read", "Bash(git status:*)", "Grep"]


def test_an_unclosed_specifier_is_not_split(tmp_path: Path) -> None:
    assert _agent(tmp_path, "tools: Read, Bash(git status\n").tools == ["Read", "Bash(git status"]


@pytest.mark.parametrize(
    ("line", "tools"),
    [
        ("Read, WebFetch(, Bash, Write", ["Read", "WebFetch(", "Bash", "Write"]),
        ("WebFetch(, Bash, Write", ["WebFetch(", "Bash", "Write"]),  # the open bracket at the start
        ("Read, Bash, WebFetch(", ["Read", "Bash", "WebFetch("]),  # and at the end
        (
            "Read, Bash(a(b, Write, Edit",
            ["Read", "Bash(a(b", "Write", "Edit"],
        ),  # nested, none closed
        (
            "Read, Bash(a(b), Write, Edit",
            ["Read", "Bash(a(b)", "Write", "Edit"],
        ),  # nested, one closed
        (
            "Read Bash(git status:*), WebFetch(, Write",
            ["Read", "Bash(git status:*)", "WebFetch(", "Write"],
        ),
    ],
)
def test_an_unclosed_bracket_hides_no_tool_after_it(
    tmp_path: Path, line: str, tools: list[str]
) -> None:
    """A stray open bracket must not swallow the rest of the line: the tools after it are split at commas, as
    before the one-pass split, so the audit still sees them."""
    assert _agent(tmp_path, f"tools: {line}\n").tools == tools


def test_tools_after_an_unclosed_bracket_still_get_their_chain(tmp_path: Path) -> None:
    agent = _agent(tmp_path, "tools: Read, WebFetch(, Bash, Write\n")
    assert any(c.tools == ["Read", "Bash"] for c in agent_chains(agent, typed=True))


@pytest.mark.parametrize(
    ("line", "tools"),
    [
        ("x), Bash, WebFetch", ["x)", "Bash", "WebFetch"]),
        ("Read), Bash(git status:*), WebFetch", ["Read)", "Bash(git status:*)", "WebFetch"]),
        (")), Read Grep", ["))", "Read", "Grep"]),
    ],
)
def test_a_stray_closing_bracket_does_not_join_the_tools_after_it(
    tmp_path: Path, line: str, tools: list[str]
) -> None:
    assert _agent(tmp_path, f"tools: {line}\n").tools == tools


def _split_seconds(tokens: int) -> float:
    text = "Read Grep " * tokens
    return min(timeit.repeat(lambda: _split_tools(text), number=1, repeat=5))


def test_the_tool_list_split_scales_linearly() -> None:
    """Four times the text takes about four times as long. A lookahead that scans to the end of the line at every
    separator takes about sixteen times. The bound is a ratio, so a slow runner does not move it."""
    assert len(_split_tools("Read Grep " * 20_000)) == 40_001
    small, large = _split_seconds(5_000), _split_seconds(20_000)
    assert large < 9 * small, (small, large)


def test_a_tools_line_of_a_megabyte_is_read(tmp_path: Path) -> None:
    agent = _agent(tmp_path, "tools: " + "Read Grep " * 100_000 + "\n")
    assert agent.tools == ["Read", "Grep"]


def test_a_yaml_list_entry_with_spaces_is_several_tools(tmp_path: Path) -> None:
    assert _agent(tmp_path, "tools:\n  - Read Grep\n  - Bash\n").tools == ["Read", "Grep", "Bash"]


def test_a_wildcard_alone_is_unrestricted_and_gets_sa007(tmp_path: Path) -> None:
    scan = _load(tmp_path, 'tools: "*"\n')
    assert declared_tools(scan.agents[0]) is None
    assert _rules(scan) == ["SA007"]


@pytest.mark.parametrize("line", ["tools:\n", "tools: []\n", 'tools: ""\n'])
def test_an_empty_tools_value_is_an_empty_declared_set_not_inherited(
    tmp_path: Path, line: str
) -> None:
    scan = _load(tmp_path, line)
    assert declared_tools(scan.agents[0]) == []
    assert _rules(scan) == []  # no SA007: nothing is inherited, and no chain
    assert build_baseline(scan).agents["helper"].tools == []


def test_allowed_tools_is_read_as_the_tool_list(tmp_path: Path) -> None:
    agent = _agent(tmp_path, "allowed-tools: Read, WebFetch\n")
    assert agent.tools == ["Read", "WebFetch"]
    assert agent.line_of("tools") == 4  # findings point at the key the file uses


def test_tools_wins_over_allowed_tools(tmp_path: Path) -> None:
    assert _agent(tmp_path, "tools: Read\nallowed-tools: Read, WebFetch\n").tools == ["Read"]


def test_webfetch_confined_to_a_domain_gives_no_chain(tmp_path: Path) -> None:
    agent = _agent(tmp_path, "tools: Read, WebFetch(domain:docs.example.org)\n")
    assert agent_chains(agent, typed=True) == []


@pytest.mark.parametrize(
    "sink",
    ["WebFetch", "WebFetch(*)", "Bash", "Bash(*)", "Bash(git push:*)", "Bash(git status:*)"],
)
def test_an_open_sink_still_gives_its_chain(tmp_path: Path, sink: str) -> None:
    agent = _agent(tmp_path, f"tools: Read, {sink}\n")
    assert any(c.tools == ["Read", sink] for c in agent_chains(agent, typed=True))


# ── Change 4: egress means sending to someone else ───────────────────


@pytest.mark.parametrize("tool", ["mcp__tracker__create_issue", "mcp__tracker__update_issue"])
def test_a_create_or_update_tool_is_a_write_not_egress(tool: str) -> None:
    assert canonical_tool_name(tool) == tool
    assert tool_roles(tool) == {"high_impact"}


@pytest.mark.parametrize("tool", ["SendMessage", "PushNotification"])
def test_the_two_messaging_tools_are_internal(tmp_path: Path, tool: str) -> None:
    assert tool_roles(tool) == frozenset()
    assert agent_chains(_agent(tmp_path, f"tools: Read, {tool}\n"), typed=True) == []


@pytest.mark.parametrize("tool", ["mcp__chat__send_message", "mcp__chat__post_reply"])
def test_a_send_tool_stays_egress(tool: str) -> None:
    assert canonical_tool_name(tool) == "send_email"
    assert "egress" in tool_roles(tool)
