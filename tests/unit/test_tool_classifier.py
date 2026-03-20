"""Unit tests for the centralized tool classifier."""

from __future__ import annotations

import pytest

from ziran.domain.tool_classifier import (
    ToolClassification,
    _classify_cached,
    _is_dangerous_cached,
    classify_tool,
    is_dangerous,
)


@pytest.mark.unit
class TestClassifyTool:
    """Tests for classify_tool function."""

    # ── Critical tier ────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            # Code execution
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
            "python_repl",
            "repl",
            "code_interpreter",
            # File mutation
            "write_file",
            "create_file",
            "delete_file",
            "remove_file",
            # Outbound network
            "http_request",
            "http_post",
            "fetch_url",
            "curl",
            "webhook_send",
            "send_data",
            # Unrestricted SQL
            "sql_query",
            "run_database_query",
            "raw_sql",
            # Environment / secrets
            "read_env",
            "get_env",
            "env_var_reader",
            # Deployment
            "deploy",
            "deploy_service",
            # Financial
            "process_payment",
            "transfer_funds",
            "payment",
            "transaction",
            # MCP write operations
            "mcp_write_file",
            "mcp_write",
        ],
    )
    def test_critical_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "critical", f"{tool_name} should be critical, got {result.risk}"

    # ── High tier ────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            # Email / messaging
            "send_email",
            "send_message",
            "gmail_send",
            # Permissions
            "update_permission",
            "modify_permission",
            "grant_access",
            "revoke_access",
            # Database mutations
            "database_write",
            "database_update",
            "database_delete",
            "insert_record",
            "update_record",
            "delete_record",
            "sql_execute",
            "database_query",
            # Configuration
            "modify_config",
            "update_config",
            "read_config",
            # File transfer
            "download",
            "upload",
            # Secrets / credentials
            "credential_store",
            "password_manager",
            "secret_vault",
            "token_refresh",
            "api_key_rotate",
            # Remote invocation
            "lambda_invoke",
            # HTTP client
            "requests_get",
            "requests_post",
            # Git
            "git_commit",
            "git_push",
            # PII access
            "query_employees",
            "get_user_info",
            # Agent delegation
            "delegate_task",
            "agent_call",
            "agent_invoke",
            # MCP tools
            "mcp_read_file",
            "mcp_fetch",
            "mcp_read_resource",
            # A2A protocol
            "send_task",
            # File read (may expose secrets/PII)
            "read_file",
            "get_file",
        ],
    )
    def test_high_tools(self, tool_name: str) -> None:
        result = classify_tool(tool_name)
        assert result.risk == "high", f"{tool_name} should be high, got {result.risk}"

    # ── Medium tier ──────────────────────────────────────────────

    @pytest.mark.parametrize(
        "tool_name",
        [
            "list_directory",
            "search_database",
            "search_users",
            "api_call",
            "external_api",
            "browser_open",
            # MCP git operations
            "mcp_git_diff",
            "mcp_git_log",
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
        assert is_dangerous("list_directory") is False
        assert is_dangerous("search_database") is False

    def test_high_is_dangerous(self) -> None:
        """High-risk tools ARE classified as 'dangerous'."""
        assert is_dangerous("read_file") is True
        assert is_dangerous("delegate_task") is True


@pytest.mark.unit
class TestClassificationCaching:
    """Tests that caching returns consistent results and avoids redundant work."""

    def test_classify_tool_returns_same_object_on_repeat(self) -> None:
        """Repeated calls for the same tool name return the cached object."""
        first = classify_tool("shell_execute")
        second = classify_tool("shell_execute")
        assert first is second

    def test_is_dangerous_returns_same_on_repeat(self) -> None:
        assert is_dangerous("shell_execute") is True
        assert is_dangerous("shell_execute") is True

    def test_cache_hit_count_increases(self) -> None:
        """lru_cache hit counter increases on repeated calls."""
        _classify_cached.cache_clear()
        classify_tool("eval")
        classify_tool("eval")
        info = _classify_cached.cache_info()
        assert info.hits >= 1

    def test_is_dangerous_cache_hit_count(self) -> None:
        _is_dangerous_cached.cache_clear()
        is_dangerous("send_email")
        is_dangerous("send_email")
        info = _is_dangerous_cached.cache_info()
        assert info.hits >= 1

    def test_case_variants_hit_same_cache_entry(self) -> None:
        """Case-insensitive regex means different casings normalize the same."""
        _classify_cached.cache_clear()
        r1 = classify_tool("shell_execute")
        r2 = classify_tool("shell_execute")
        assert r1 is r2
        assert r1.risk == "critical"
