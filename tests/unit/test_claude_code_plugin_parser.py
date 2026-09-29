"""Tests for the Claude Code plugin / subagent parser."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from ziran.domain.entities.claude_code import CLAUDE_CODE_BUILTIN_TOOLS, ClaudeCodeScan
from ziran.infrastructure.config.claude_code_plugin import MAX_FILE_BYTES, load_claude_code

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "claude_code"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _agent_md(name: str, tools: str | None = "Read") -> str:
    tools_line = f"tools: {tools}\n" if tools is not None else ""
    return f"---\nname: {name}\n{tools_line}---\nBody.\n"


def _manifest(root: Path, data: dict[str, Any]) -> None:
    _write(root / ".claude-plugin" / "plugin.json", json.dumps(data))


def _messages(scan: ClaudeCodeScan) -> list[str]:
    return [i.message for i in scan.issues]


@pytest.mark.integration
class TestFixtures:
    def test_vulnerable_plugin(self) -> None:
        scan = load_claude_code(FIXTURES / "vulnerable_plugin")
        assert scan.detected
        assert scan.issues == []
        assert scan.files_analyzed == 5
        assert scan.plugin is not None
        assert (scan.plugin.name, scan.plugin.version) == ("vulnerable-plugin", "0.1.0")
        assert [a.name for a in scan.agents] == ["generalist", "researcher"]
        generalist, researcher = scan.agents
        assert generalist.unrestricted
        assert generalist.effective_tools == list(CLAUDE_CODE_BUILTIN_TOOLS)
        assert researcher.tools == ["Read", "Grep", "WebFetch", "mcp__slack__send_message"]
        assert [c.id for c in researcher.capabilities] == researcher.tools
        assert researcher.line_of("tools") == 4
        assert researcher.body_line == 7
        assert researcher.file.endswith("researcher.md")
        assert [(h.event, h.matcher, h.type) for h in scan.hooks] == [
            ("PreToolUse", "Bash", "command")
        ]
        assert [(s.name, s.transport) for s in scan.mcp_servers] == [("slack", "streamable-http")]

    def test_safe_plugin(self) -> None:
        scan = load_claude_code(FIXTURES / "safe_plugin")
        assert scan.issues == []
        assert scan.files_analyzed == 5
        assert [a.name for a in scan.agents] == ["reviewer", "summarizer"]
        assert [a.tools for a in scan.agents] == [["Read", "Grep", "Glob"], ["Read", "Grep"]]
        assert not any(c.dangerous for a in scan.agents for c in a.capabilities)
        assert [(s.name, s.transport) for s in scan.mcp_servers] == [("docs", "stdio")]

    @pytest.mark.parametrize("sub", ["malformed", "malformed/agents"])
    def test_malformed(self, sub: str) -> None:
        scan = load_claude_code(FIXTURES / sub)
        assert [a.name for a in scan.agents] == ["ok"]
        assert scan.files_analyzed == 2
        [issue] = scan.issues
        assert issue.file.endswith("broken.md")
        assert issue.line == 3
        assert issue.message.startswith("invalid YAML frontmatter")
        assert "ziran-fake-secret-0416" not in issue.message

    def test_single_agent_file(self) -> None:
        scan = load_claude_code(FIXTURES / "vulnerable_plugin" / "agents" / "researcher.md")
        assert [a.name for a in scan.agents] == ["researcher"]
        assert scan.files_analyzed == 1


@pytest.mark.unit
class TestAgentFiles:
    def test_unclosed_fence(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", "---\nname: a\n")
        scan = load_claude_code(tmp_path)
        assert [(i.line, i.message) for i in scan.issues] == [
            (1, "frontmatter is not closed with '---'")
        ]
        assert scan.agents == []

    def test_not_a_mapping(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", "---\n- a\n---\n")
        scan = load_claude_code(tmp_path)
        assert [(i.line, i.message) for i in scan.issues] == [
            (2, "frontmatter must be a YAML mapping")
        ]

    def test_empty_frontmatter(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", "---\n---\n")
        [issue] = load_claude_code(tmp_path).issues
        assert issue.line == 1
        assert issue.message.startswith("invalid frontmatter field 'name'")

    def test_missing_name(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", "---\ndescription: d\n---\n")
        scan = load_claude_code(tmp_path)
        [issue] = scan.issues
        assert (issue.line, issue.message.startswith("invalid frontmatter field 'name'")) == (
            1,
            True,
        )
        assert scan.agents == []

    def test_bad_tools_line(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", "---\nname: a\ntools: [Read, 3]\n---\n")
        scan = load_claude_code(tmp_path)
        [issue] = scan.issues
        assert issue.line == 3
        assert "'tools'" in issue.message
        assert scan.agents == []

    def test_duplicate_name(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", _agent_md("x"))
        _write(tmp_path / ".claude" / "agents" / "b.md", _agent_md("x", "Bash"))
        scan = load_claude_code(tmp_path)
        assert [a.file for a in scan.agents] == [str(tmp_path / "agents" / "a.md")]
        [issue] = scan.issues
        assert issue.file.endswith("b.md")
        assert issue.line == 2
        assert issue.message.startswith("duplicate agent name 'x'")

    def test_readme_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "README.md", "# Agents\n")
        _write(tmp_path / "agents" / "a.md", _agent_md("a"))
        scan = load_claude_code(tmp_path)
        assert [a.name for a in scan.agents] == ["a"]
        assert scan.issues == []
        assert scan.files_analyzed == 1

    def test_bom_and_body(self, tmp_path: Path) -> None:
        path = tmp_path / "agents" / "a.md"
        path.parent.mkdir()
        path.write_bytes(b"\xef\xbb\xbf---\nname: a\n---\nline one\nline two\n")
        [agent] = load_claude_code(tmp_path).agents
        assert (agent.system_prompt, agent.body_line, agent.key_lines) == (
            "line one\nline two",
            4,
            {"name": 2},
        )

    def test_too_large(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", _agent_md("a") + "x" * MAX_FILE_BYTES)
        scan = load_claude_code(tmp_path)
        assert scan.agents == []
        assert len(scan.issues) == 1
        assert scan.files_analyzed == 0

    def test_undecodable(self, tmp_path: Path) -> None:
        path = tmp_path / "agents" / "a.md"
        path.parent.mkdir()
        path.write_bytes(b"---\nname: \xff\n---\n")
        scan = load_claude_code(tmp_path)
        assert len(scan.issues) == 1
        assert scan.files_analyzed == 0

    def test_unreadable(self, tmp_path: Path) -> None:
        (tmp_path / "agents" / "dir.md").mkdir(parents=True)
        scan = load_claude_code(tmp_path)
        assert len(scan.issues) == 1
        assert scan.issues[0].line is None

    @pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX non-root")
    def test_permission_denied_never_raises(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", _agent_md("a"))
        _write(tmp_path / ".claude" / "agents" / "b.md", _agent_md("b"))
        (tmp_path / "agents").chmod(0)
        (tmp_path / ".claude" / "agents" / "b.md").chmod(0)
        try:
            scan = load_claude_code(tmp_path)
        finally:
            (tmp_path / "agents").chmod(0o755)
        assert scan.agents == []
        assert [i.file.rsplit("/", 1)[-1] for i in scan.issues] == ["b.md"]

    def test_symlink_outside_root(self, tmp_path: Path) -> None:
        outside = _write(tmp_path / "outside" / "x.md", _agent_md("x"))
        root = tmp_path / "plugin"
        (root / "agents").mkdir(parents=True)
        (root / "agents" / "x.md").symlink_to(outside)
        scan = load_claude_code(root)
        assert scan.agents == []
        assert len(scan.issues) == 1

    def test_secret_hygiene(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "agents" / "a.md", "---\nname: 5\ndescription: ziran-fake-secret-0417\n---\n"
        )
        _write(
            tmp_path / "agents" / "b.md", "---\nname: b\ntools: ziran-fake-secret-0418: x\n---\n"
        )
        scan = load_claude_code(tmp_path)
        assert len(scan.issues) == 2
        for message in _messages(scan):
            assert "ziran-fake-secret" not in message


@pytest.mark.unit
class TestDiscovery:
    @pytest.mark.parametrize("name", ["app.py", "missing"])
    def test_not_claude_code_path(self, tmp_path: Path, name: str) -> None:
        _write(tmp_path / "app.py", "print('hi')\n")
        scan = load_claude_code(tmp_path / name)
        assert not scan.detected
        assert scan.issues == []

    def test_python_repo_mcp_not_read(self, tmp_path: Path) -> None:
        _write(tmp_path / "app.py", "print('hi')\n")
        _write(tmp_path / ".mcp.json", "{not json")
        scan = load_claude_code(tmp_path)
        assert not scan.detected
        assert (scan.issues, scan.mcp_servers, scan.files_analyzed) == ([], [], 0)

    def test_agents_dir_directly(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", _agent_md("a"))
        _write(tmp_path / "agents" / "sub" / "x.md", _agent_md("x"))
        scan = load_claude_code(tmp_path / "agents")
        assert [a.name for a in scan.agents] == ["a"]

    def test_dot_claude_dir(self, tmp_path: Path) -> None:
        _write(tmp_path / ".claude" / "agents" / "a.md", _agent_md("a"))
        assert [a.name for a in load_claude_code(tmp_path / ".claude").agents] == ["a"]

    @pytest.mark.parametrize("value", ["./extra/", ["./extra/one.md"]])
    def test_manifest_agent_paths(self, tmp_path: Path, value: object) -> None:
        _manifest(tmp_path, {"name": "p", "agents": value})
        _write(tmp_path / "extra" / "one.md", _agent_md("one"))
        scan = load_claude_code(tmp_path)
        assert [a.name for a in scan.agents] == ["one"]
        assert scan.issues == []

    @pytest.mark.parametrize(
        ("value", "fragment"),
        [
            ("../outside", "escapes the plugin root"),
            ("./missing", "not found"),
            (3, "agents"),
        ],
    )
    def test_manifest_bad_agent_paths(self, tmp_path: Path, value: object, fragment: str) -> None:
        _write(tmp_path / "outside" / "x.md", _agent_md("x"))
        root = tmp_path / "plugin"
        _manifest(root, {"name": "p", "agents": value})
        scan = load_claude_code(root)
        assert scan.agents == []
        [issue] = scan.issues
        assert fragment in issue.message
        assert issue.line is None

    def test_inline_components_ignored(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"name": "p", "hooks": {"Stop": []}, "mcpServers": {"x": {}}})
        scan = load_claude_code(tmp_path)
        assert scan.issues == []
        assert scan.plugin is not None
        assert scan.files_analyzed == 1

    def test_manifest_component_files(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"name": "p", "hooks": "./h.json", "mcpServers": ["./m.json"]})
        hook = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}]}}
        _write(tmp_path / "h.json", json.dumps(hook))
        _write(tmp_path / "m.json", json.dumps({"mcpServers": {"s": {"command": "x"}}}))
        scan = load_claude_code(tmp_path)
        assert [h.event for h in scan.hooks] == ["Stop"]
        assert [s.name for s in scan.mcp_servers] == ["s"]
        assert scan.files_analyzed == 3


@pytest.mark.unit
class TestJsonFiles:
    def test_invalid_plugin_json(self, tmp_path: Path) -> None:
        _write(tmp_path / ".claude-plugin" / "plugin.json", '{"name": "p",\n oops}')
        _write(tmp_path / "agents" / "a.md", _agent_md("a"))
        scan = load_claude_code(tmp_path)
        assert scan.plugin is None
        assert [a.name for a in scan.agents] == ["a"]
        assert [(i.line, i.message) for i in scan.issues] == [(2, "invalid JSON")]

    def test_plugin_json_not_object(self, tmp_path: Path) -> None:
        _write(tmp_path / ".claude-plugin" / "plugin.json", "[]")
        assert _messages(load_claude_code(tmp_path)) == ["expected a JSON object"]

    def test_plugin_json_without_name(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"version": "1"})
        scan = load_claude_code(tmp_path)
        assert scan.plugin is None
        [message] = _messages(scan)
        assert message.startswith("invalid plugin.json field 'name'")

    def test_hooks_invalid_json(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"name": "p"})
        _write(tmp_path / "hooks" / "hooks.json", "{\n\n,")
        [issue] = load_claude_code(tmp_path).issues
        assert (issue.line, issue.message) == (3, "invalid JSON")

    def test_hooks_without_hooks_object(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"name": "p"})
        _write(tmp_path / "hooks" / "hooks.json", '{"hooks": []}')
        assert _messages(load_claude_code(tmp_path)) == ["expected a 'hooks' object"]

    def test_malformed_hook_entries(self, tmp_path: Path) -> None:
        _manifest(tmp_path, {"name": "p"})
        hooks = {
            "hooks": {
                "Stop": ["x"],
                "Start": "x",
                "Bad": [{"hooks": ["x", {"type": 3}]}],
                "PreToolUse": [{"hooks": [{"type": "prompt", "prompt": "check"}]}],
            }
        }
        _write(tmp_path / "hooks" / "hooks.json", json.dumps(hooks))
        scan = load_claude_code(tmp_path)
        assert _messages(scan) == [
            "malformed hook entry for event 'Stop'",
            "malformed hook entry for event 'Start'",
            "malformed hook entry for event 'Bad'",
            "malformed hook entry for event 'Bad'",
        ]
        [hook] = scan.hooks
        assert (hook.event, hook.matcher, hook.type, hook.command) == (
            "PreToolUse",
            None,
            "prompt",
            None,
        )

    def test_unread_json_files(self, tmp_path: Path) -> None:
        outside = _write(tmp_path / "outside.json", json.dumps({"mcpServers": {"s": {}}}))
        root = tmp_path / "plugin"
        _manifest(root, {"name": "p"})
        _write(root / "hooks" / "hooks.json", " " * (MAX_FILE_BYTES + 1))
        (root / ".mcp.json").symlink_to(outside)
        scan = load_claude_code(root)
        assert [i.file.rsplit("/", 1)[-1] for i in scan.issues] == ["hooks.json", ".mcp.json"]
        assert (scan.hooks, scan.mcp_servers, scan.files_analyzed) == ([], [], 1)

    def test_mcp_loader_error(self, tmp_path: Path) -> None:
        _write(tmp_path / "agents" / "a.md", _agent_md("a"))
        _write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {"x": {"type": "ws"}}}))
        scan = load_claude_code(tmp_path)
        assert scan.mcp_servers == []
        [message] = _messages(scan)
        assert "unsupported type" in message
