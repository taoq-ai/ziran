"""Tests for the Claude Code tool-name alias map (#417)."""

from __future__ import annotations

import pytest

from ziran.application.knowledge_graph.tool_aliases import (
    UNRESTRICTED_EXEC_TOOLS,
    canonical_tool_name,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("tool_id", "expected"),
    [
        # Built-in tools
        ("Read", "read_file"),
        ("Grep", "read_file"),
        ("Glob", "read_file"),
        ("Write", "write_file"),
        ("Edit", "write_file"),
        ("NotebookEdit", "write_file"),
        ("Bash", "shell_execute"),
        ("WebFetch", "http_request"),
        ("WebSearch", "browse_url"),
        ("Agent", "spawn_subagent"),
        # MCP outbound tools
        ("mcp__slack__slack_send_message", "send_email"),
        ("mcp__slack__slack_post_message", "send_email"),
        ("mcp__slack__slack_reply_to_thread", "send_email"),
        ("mcp__github__create_issue", "send_email"),
        ("mcp__github__update_pull_request", "send_email"),
        ("mcp__x__publish_post", "send_email"),
        # MCP non-outbound tools stay unchanged
        ("mcp__slack__slack_list_channels", "mcp__slack__slack_list_channels"),
        ("mcp__filesystem__read_file", "mcp__filesystem__read_file"),
        ("mcp__slack", "mcp__slack"),
        # Permission-rule form
        ("Read(./.env)", "read_secret_file"),
        ("Read(~/.ssh/id_rsa)", "read_secret_file"),
        ("Grep(.aws/credentials)", "read_secret_file"),
        ("Read(certs/server.pem)", "read_secret_file"),
        ("Read(src/main.py)", "read_file"),
        ("Bash(git push:*)", "git_push"),
        ("Bash(git push origin main)", "git_push"),
        ("Bash(npm test:*)", "shell_execute"),
        # Regression: non-Claude-Code ids are unchanged
        ("read_file", "read_file"),
        ("Read_File", "Read_File"),
        ("read", "read"),
        ("bash", "bash"),
        ("tool_http_request", "tool_http_request"),
        ("harmless_a", "harmless_a"),
    ],
)
def test_canonical_tool_name(tool_id: str, expected: str) -> None:
    assert canonical_tool_name(tool_id) == expected


@pytest.mark.unit
def test_unrestricted_exec_tools() -> None:
    assert frozenset({"Bash", "Bash(*)"}) == UNRESTRICTED_EXEC_TOOLS
