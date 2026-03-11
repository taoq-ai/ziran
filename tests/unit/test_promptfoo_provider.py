"""Tests for the Promptfoo provider bridge."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ziran.integrations.promptfoo.assertions import get_assert
from ziran.integrations.promptfoo.provider import _run_single_prompt, call_api

# ── Provider tests ────────────────────────────────────────────────────


def _make_mock_response(
    content: str = "test response",
    tool_calls: list[dict[str, Any]] | None = None,
) -> AsyncMock:
    mock = AsyncMock()
    mock.content = content
    mock.tool_calls = tool_calls or []
    mock.prompt_tokens = 10
    mock.completion_tokens = 20
    mock.total_tokens = 30
    return mock


class TestCallApi:
    def test_missing_target_url(self) -> None:
        """Should return error when target_url is not configured."""
        result = call_api("test prompt", options={})

        assert "error" in result
        assert "target_url" in result["error"].lower()

    def test_missing_target_url_in_config(self) -> None:
        result = call_api("test prompt", options={"config": {}})

        assert "error" in result

    def test_none_options_handled(self) -> None:
        """Should handle None options gracefully."""
        result = call_api("test", options=None)

        assert "error" in result

    @patch("ziran.integrations.promptfoo.provider._run_analysis")
    def test_delegates_to_run_analysis(self, mock_run: AsyncMock) -> None:
        """call_api should delegate to _run_analysis for valid config."""
        mock_run.return_value = {"output": "mocked", "tokenUsage": {}}

        result = call_api(
            "test prompt",
            options={"config": {"target_url": "http://localhost:8000"}},
        )

        assert result["output"] == "mocked"
        mock_run.assert_called_once()

    @patch("ziran.integrations.promptfoo.provider._run_analysis")
    def test_exception_returns_error(self, mock_run: AsyncMock) -> None:
        """Should return error dict on exception."""
        mock_run.side_effect = ValueError("Connection failed")

        result = call_api(
            "test",
            options={"config": {"target_url": "http://localhost:8000"}},
        )

        assert "error" in result
        assert "Connection failed" in result["error"]


class TestRunSinglePrompt:
    @pytest.mark.asyncio
    async def test_returns_output(self) -> None:
        """Should return output from adapter invoke."""
        mock_adapter = AsyncMock()
        mock_adapter.invoke = AsyncMock(
            return_value=_make_mock_response(content="Hello from agent")
        )

        result = await _run_single_prompt(mock_adapter, "test", {})

        assert result["output"] == "Hello from agent"
        assert result["tokenUsage"]["total"] == 30
        assert result["tokenUsage"]["prompt"] == 10
        assert result["tokenUsage"]["completion"] == 20

    @pytest.mark.asyncio
    async def test_tool_call_metadata(self) -> None:
        """Should include tool call metadata."""
        mock_adapter = AsyncMock()
        mock_adapter.invoke = AsyncMock(
            return_value=_make_mock_response(
                content="Done",
                tool_calls=[{"name": "read_file", "arguments": {"path": "/etc/passwd"}}],
            )
        )

        result = await _run_single_prompt(mock_adapter, "test", {})

        assert result["metadata"]["has_tool_calls"] is True
        assert result["metadata"]["tool_call_count"] == 1

    @pytest.mark.asyncio
    async def test_indicator_matching(self) -> None:
        """Should match success indicators in response."""
        mock_adapter = AsyncMock()
        mock_adapter.invoke = AsyncMock(
            return_value=_make_mock_response(content="Here is the secret data and the API key")
        )

        result = await _run_single_prompt(
            mock_adapter,
            "test",
            {"success_indicators": ["secret", "api key", "password"]},
        )

        assert "secret" in result["metadata"]["matched_indicators"]
        assert "api key" in result["metadata"]["matched_indicators"]
        assert result["metadata"]["indicator_match_rate"] == pytest.approx(2 / 3)

    @pytest.mark.asyncio
    async def test_no_indicators_config(self) -> None:
        """Should work without success_indicators in config."""
        mock_adapter = AsyncMock()
        mock_adapter.invoke = AsyncMock(return_value=_make_mock_response())

        result = await _run_single_prompt(mock_adapter, "test", {})

        assert "matched_indicators" not in result["metadata"]


# ── Assertions tests ──────────────────────────────────────────────────


class TestGetAssert:
    def test_all_pass_no_config(self) -> None:
        """With no config, should pass by default."""
        result = get_assert("some output")

        assert result["pass"] is True
        assert result["score"] == 1.0

    def test_vulnerability_count_pass(self) -> None:
        result = get_assert(
            "scan output",
            context={
                "config": {"max_vulnerabilities": 5},
                "metadata": {"total_vulnerabilities": 3},
            },
        )

        assert result["pass"] is True
        assert result["score"] == 1.0

    def test_vulnerability_count_fail(self) -> None:
        result = get_assert(
            "scan output",
            context={
                "config": {"max_vulnerabilities": 0},
                "metadata": {"total_vulnerabilities": 3},
            },
        )

        assert result["pass"] is False
        assert result["score"] < 1.0
        assert "vulnerabilities" in result["reason"].lower()

    def test_trust_score_pass(self) -> None:
        result = get_assert(
            "scan output",
            context={
                "config": {"min_trust_score": 0.7},
                "metadata": {"trust_score": 0.9},
            },
        )

        assert result["pass"] is True

    def test_trust_score_fail(self) -> None:
        result = get_assert(
            "scan output",
            context={
                "config": {"min_trust_score": 0.8},
                "metadata": {"trust_score": 0.5},
            },
        )

        assert result["pass"] is False
        assert "trust score" in result["reason"].lower()

    def test_tool_call_count_fail(self) -> None:
        result = get_assert(
            "output",
            context={
                "config": {"max_tool_calls": 0},
                "metadata": {"tool_call_count": 3},
            },
        )

        assert result["pass"] is False
        assert "tool calls" in result["reason"].lower()

    def test_blocked_indicators_fail(self) -> None:
        result = get_assert(
            "Here is the SECRET password and API_KEY",
            context={
                "config": {"blocked_indicators": ["secret", "api_key"]},
            },
        )

        assert result["pass"] is False
        assert result["score"] <= 0.3
        assert "blocked" in result["reason"].lower()

    def test_blocked_indicators_pass(self) -> None:
        result = get_assert(
            "I cannot share that information.",
            context={
                "config": {"blocked_indicators": ["secret", "password"]},
            },
        )

        assert result["pass"] is True

    def test_multiple_failures(self) -> None:
        """Multiple assertion failures should all be reported."""
        result = get_assert(
            "output with secret",
            context={
                "config": {
                    "max_vulnerabilities": 0,
                    "min_trust_score": 0.9,
                    "blocked_indicators": ["secret"],
                },
                "metadata": {
                    "total_vulnerabilities": 5,
                    "trust_score": 0.3,
                },
            },
        )

        assert result["pass"] is False
        assert "vulnerabilities" in result["reason"].lower()
        assert "trust score" in result["reason"].lower()
        assert "blocked" in result["reason"].lower()

    def test_none_context_handled(self) -> None:
        result = get_assert("output", context=None)

        assert result["pass"] is True
