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
        # LangChain-style RAG tool names (spec 056)
        ("recursive_url_loader", "http_request"),
        ("tool_recursive_url_loader", "http_request"),
        ("RecursiveUrlLoader", "http_request"),
        ("recursive-url-loader", "http_request"),
        ("tavily_search", "browse_url"),
        ("tool_tavily_search", "browse_url"),
        ("TavilySearch", "browse_url"),
        ("tavily_search_results", "browse_url"),
        ("tavily_search_results_json", "browse_url"),
        ("TavilySearchResults", "browse_url"),
        ("vector_store_query", "vector_store_read"),
        ("tool_vector_store_query", "vector_store_read"),
        ("vectorstore_query", "vector_store_read"),
        ("VectorStoreQuery", "vector_store_read"),
        ("vector_store_search", "vector_store_read"),
        ("vectorstore_search", "vector_store_read"),
        # Names that only share a word with them stay unchanged
        ("search", "search"),
        ("web_search", "web_search"),
        ("url_loader", "url_loader"),
        ("vector_store_write", "vector_store_write"),
        # Ids that only contain one of the names keep their own words
        ("shell_execute_tavily_search", "shell_execute_tavily_search"),
        ("mcp__x__shell_execute_tavily_search", "mcp__x__shell_execute_tavily_search"),
        ("tavily_search_and_send_email", "tavily_search_and_send_email"),
        ("vectorstore_search_database", "vectorstore_search_database"),
        ("vector_store_query_writer", "vector_store_query_writer"),
        ("save_vectors_to_research_db", "save_vectors_to_research_db"),
        ("recursive_url_loader_write_file", "recursive_url_loader_write_file"),
        ("Foo(tavily_search)", "Foo(tavily_search)"),
        # MCP ids are not mapped: the server name can carry capability words
        ("mcp__send_email__tavily_search", "mcp__send_email__tavily_search"),
        ("mcp__shell_execute__tavily_search", "mcp__shell_execute__tavily_search"),
        ("mcp__tavily__tavily_search", "mcp__tavily__tavily_search"),
        ("mcp__tavily__tavily-search", "mcp__tavily__tavily-search"),
        # Claude Code rules keep precedence over the LangChain-style names
        ("Read(notes/tavily_search.md)", "read_file"),
        ("mcp__tavily__send_tavily_search_digest", "send_email"),
    ],
)
def test_canonical_tool_name(tool_id: str, expected: str) -> None:
    assert canonical_tool_name(tool_id) == expected


@pytest.mark.unit
def test_unrestricted_exec_tools() -> None:
    assert frozenset({"Bash", "Bash(*)"}) == UNRESTRICTED_EXEC_TOOLS
