"""Unit tests for the centralized tool classifier."""

from __future__ import annotations

import pytest

from ziran.domain.tool_classifier import ToolClassification, classify_tool, is_dangerous


@pytest.mark.unit
class TestClassifyTool:
    """Tests for classify_tool function."""

    # ── Critical tier ────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            "shell_execute",
            "bash_run",
            "execute_code",
            "exec_code",
            "run_code",
            "eval",
            "safe_eval",
            "terminal_exec",
            "subprocess_call",
            "system_command",
            "write_file",
            "create_file",
            "delete_file",
            "remove_file",
            "http_request",
            "http_post",
            "fetch_url",
            "curl",
            "webhook_send",
            "send_data",
        ],
    )
    def test_critical_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "critical", f"{tool_name} should be critical, got {result.risk}"

    # ── High tier ────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            "send_email",
            "send_message",
            "update_permission",
            "modify_permission",
            "grant_access",
            "revoke_access",
            "database_write",
            "database_update",
            "database_delete",
            "insert_record",
            "update_record",
            "delete_record",
            "sql_execute",
            "modify_config",
            "update_config",
            "download",
            "upload",
            "credential_store",
            "password_manager",
            "secret_vault",
            "token_refresh",
            "api_key_rotate",
            "lambda_invoke",
        ],
    )
    def test_high_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "high", f"{tool_name} should be high, got {result.risk}"

    # ── Medium tier ──────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            "read_file",
            "get_file",
            "list_directory",
            "search_database",
            "database_query",
            "sql_query",
            "get_user_info",
            "search_users",
            "api_call",
            "external_api",
            "browser_open",
        ],
    )
    def test_medium_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "medium", f"{tool_name} should be medium, got {result.risk}"

    # ── Low tier (no match) ──────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            "classify_text",
            "search_knowledge_base",
            "get_weather",
            "hello_world",
            "custom_benign_tool",
        ],
    )
    def test_low_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "low", f"{tool_name} should be low, got {result.risk}"

    # ── Word-boundary precision ──────────────────────────────────

    def test_eval_no_false_positive_on_evaluator(self) -> None:
        """'file_evaluator' should NOT match \\beval\\b."""
        result = classify_tool("file_evaluator")
        # "file" in medium patterns will match, but not eval
        assert result.risk != "critical"

    def test_shell_no_false_positive_on_nutshell(self) -> None:
        """'nutshell' should NOT match \\bshell\\b."""
        result = classify_tool("nutshell_summary")
        assert result.risk != "critical"

    def test_case_insensitive(self) -> None:
        result = classify_tool("Shell_Execute")
        assert result.risk == "critical"

    def test_returns_classification_dataclass(self) -> None:
        result = classify_tool("eval")
        assert isinstance(result, ToolClassification)
        assert result.risk == "critical"
        assert result.description != ""


@pytest.mark.unit
class TestIsDangerous:
    """Tests for is_dangerous convenience function."""

    def test_dangerous_tool(self) -> None:
        assert is_dangerous("shell_execute") is True
        assert is_dangerous("send_email") is True

    def test_safe_tool(self) -> None:
        assert is_dangerous("classify_text") is False
        assert is_dangerous("get_weather") is False

    def test_medium_not_dangerous(self) -> None:
        """Medium-risk tools are NOT classified as 'dangerous'."""
        assert is_dangerous("read_file") is False
        assert is_dangerous("search_database") is False
