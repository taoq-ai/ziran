"""Unit tests for the Claude Code domain models and tool vocabulary."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ziran.application.knowledge_graph.tool_aliases import _BUILTIN_ALIASES
from ziran.domain.entities.capability import CapabilityType
from ziran.domain.entities.claude_code import (
    CLAUDE_CODE_BUILTIN_TOOLS,
    ClaudeCodeAgent,
    ClaudeCodeParseIssue,
    ClaudeCodePlugin,
    ClaudeCodeScan,
    claude_code_tool_capability,
)

_TOOL = CapabilityType.TOOL
_DATA = CapabilityType.DATA_ACCESS
_EXT = CapabilityType.EXTERNAL_API


def _agent(**kwargs: Any) -> ClaudeCodeAgent:
    base: dict[str, Any] = {"name": "a", "file": "agents/a.md", "body_line": 5}
    return ClaudeCodeAgent.model_validate(base | kwargs)


@pytest.mark.unit
class TestVocabulary:
    def test_builtin_names_and_order(self) -> None:
        assert list(CLAUDE_CODE_BUILTIN_TOOLS) == [
            "Agent",
            "Bash",
            "Edit",
            "Glob",
            "Grep",
            "NotebookEdit",
            "Read",
            "Skill",
            "TodoWrite",
            "WebFetch",
            "WebSearch",
            "Write",
        ]

    def test_covers_alias_map(self) -> None:
        assert set(_BUILTIN_ALIASES) <= set(CLAUDE_CODE_BUILTIN_TOOLS)

    @pytest.mark.parametrize(
        ("tool", "kind", "dangerous", "permission"),
        [
            ("Bash", _TOOL, True, True),
            ("Read", _DATA, False, False),
            ("Grep", _DATA, False, False),
            ("Glob", _DATA, False, False),
            ("WebFetch", _EXT, True, True),
            ("Write", _DATA, True, True),
            ("Agent", _TOOL, True, False),
            ("Bash(npm test:*)", _TOOL, True, True),
            ("mcp__slack__send_message", _EXT, True, True),
            ("mcp__docs__search", _EXT, False, True),
            ("FooTool", _TOOL, False, False),
        ],
    )
    def test_tool_capability(
        self, tool: str, kind: CapabilityType, dangerous: bool, permission: bool
    ) -> None:
        cap = claude_code_tool_capability(tool)
        assert cap.id == cap.name == tool
        assert (cap.type, cap.dangerous, cap.requires_permission) == (kind, dangerous, permission)


@pytest.mark.unit
class TestAgentTools:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Read, Grep, Glob", ["Read", "Grep", "Glob"]),
            (["Read", " Grep "], ["Read", "Grep"]),
            ("Read, Bash(git add:*, git commit:*)", ["Read", "Bash(git add:*, git commit:*)"]),
            ("Read, Read, Grep", ["Read", "Grep"]),
            ("Read,,Grep,", ["Read", "Grep"]),
            (None, None),
            ("", None),
            ("  ", None),
            ([], None),
        ],
    )
    def test_normalisation(self, raw: object, expected: list[str] | None) -> None:
        assert _agent(tools=raw).tools == expected

    def test_absent_is_none(self) -> None:
        assert _agent().tools is None

    @pytest.mark.parametrize("raw", [["Read", 3], {"a": 1}])
    def test_invalid(self, raw: object) -> None:
        with pytest.raises(ValidationError) as info:
            _agent(tools=raw)
        assert info.value.errors()[0]["loc"][0] == "tools"

    @pytest.mark.parametrize("extra", [{}, {"name": ""}])
    def test_name_required(self, extra: dict[str, Any]) -> None:
        data: dict[str, Any] = {"file": "a.md", "body_line": 1} | extra
        with pytest.raises(ValidationError) as info:
            ClaudeCodeAgent.model_validate(data)
        assert info.value.errors()[0]["loc"][0] == "name"


@pytest.mark.unit
class TestAgentProperties:
    def test_restricted(self) -> None:
        agent = _agent(tools="Read, WebFetch")
        assert not agent.unrestricted
        assert agent.effective_tools == ["Read", "WebFetch"]
        assert [c.id for c in agent.capabilities] == ["Read", "WebFetch"]

    def test_unrestricted(self) -> None:
        agent = _agent()
        assert agent.unrestricted
        assert agent.effective_tools == list(CLAUDE_CODE_BUILTIN_TOOLS)
        assert [c.id for c in agent.capabilities] == agent.effective_tools

    def test_effective_tools_is_a_copy(self) -> None:
        agent = _agent(tools="Read")
        agent.effective_tools.append("Bash")
        assert agent.tools == ["Read"]

    def test_line_of(self) -> None:
        agent = _agent(key_lines={"name": 2, "tools": 4})
        assert agent.line_of("tools") == 4
        assert agent.line_of("model") == 1


@pytest.mark.unit
class TestScan:
    def test_empty_not_detected(self) -> None:
        assert not ClaudeCodeScan(root=".").detected

    @pytest.mark.parametrize(
        "extra",
        [
            {"plugin": ClaudeCodePlugin(name="p", file="plugin.json")},
            {"agents": [_agent()]},
            {"issues": [ClaudeCodeParseIssue(file="x.md", message="m")]},
        ],
    )
    def test_detected(self, extra: dict[str, Any]) -> None:
        assert ClaudeCodeScan(root=".", **extra).detected
