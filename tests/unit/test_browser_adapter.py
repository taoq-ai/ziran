"""Unit tests for the BrowserAgentAdapter and BrowserConfig.

Playwright is fully mocked — no real browser is launched.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.domain.entities.target import (
    BrowserConfig,
    ProtocolType,
    TargetConfig,
)

# ──────────────────────────────────────────────────────────────────────
# BrowserConfig model
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBrowserConfig:
    """Tests for BrowserConfig defaults and validation."""

    def test_defaults(self) -> None:
        cfg = BrowserConfig()
        assert cfg.browser_type == "chromium"
        assert cfg.headless is True
        assert cfg.response_timeout == 60.0
        assert cfg.settle_delay == 1.0
        assert cfg.login_url is None
        assert cfg.login_steps == []
        assert cfg.viewport_width == 1280
        assert cfg.viewport_height == 720

    def test_custom_selectors(self) -> None:
        cfg = BrowserConfig(
            input_selector="#chat-input",
            submit_selector="#send-btn",
            response_selector=".bot-message",
        )
        assert cfg.input_selector == "#chat-input"
        assert cfg.submit_selector == "#send-btn"
        assert cfg.response_selector == ".bot-message"

    def test_custom_browser_type(self) -> None:
        cfg = BrowserConfig(browser_type="firefox", headless=False)
        assert cfg.browser_type == "firefox"
        assert cfg.headless is False

    def test_api_url_pattern(self) -> None:
        cfg = BrowserConfig(
            api_url_pattern="**/api/chat/**",
            response_json_path="choices.0.message.content",
        )
        assert cfg.api_url_pattern == "**/api/chat/**"
        assert cfg.response_json_path == "choices.0.message.content"

    def test_login_steps(self) -> None:
        cfg = BrowserConfig(
            login_url="https://example.com/login",
            login_steps=[
                {"selector": "#user", "action": "fill", "value": "admin"},
                {"selector": "#pass", "action": "fill", "value": "secret"},
                {"selector": "#submit", "action": "click", "value": ""},
            ],
        )
        assert cfg.login_url == "https://example.com/login"
        assert len(cfg.login_steps) == 3


# ──────────────────────────────────────────────────────────────────────
# TargetConfig with browser protocol
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestTargetConfigBrowser:
    """Tests for TargetConfig browser protocol integration."""

    def test_browser_protocol_creates_default_config(self) -> None:
        config = TargetConfig(url="https://chat.example.com", protocol="browser")
        assert config.protocol == ProtocolType.BROWSER
        assert config.browser is not None
        assert config.browser.browser_type == "chromium"

    def test_browser_protocol_with_custom_config(self) -> None:
        config = TargetConfig(
            url="https://chat.example.com",
            protocol="browser",
            browser=BrowserConfig(headless=False, browser_type="firefox"),
        )
        assert config.browser is not None
        assert config.browser.headless is False
        assert config.browser.browser_type == "firefox"

    def test_non_browser_protocol_no_browser_config(self) -> None:
        config = TargetConfig(url="https://api.example.com", protocol="rest")
        assert config.browser is None


# ──────────────────────────────────────────────────────────────────────
# BrowserAgentAdapter smoke tests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBrowserAgentAdapterSmoke:
    """Import and instantiation smoke tests."""

    def test_import(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        assert BrowserAgentAdapter is not None

    def test_instantiation(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        config = TargetConfig(url="https://chat.example.com", protocol="browser")
        adapter = BrowserAgentAdapter(config)
        assert adapter._config == config

    def test_get_state_before_init(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        config = TargetConfig(url="https://chat.example.com", protocol="browser")
        adapter = BrowserAgentAdapter(config)
        state = adapter.get_state()
        assert state.session_id == "uninitialized"
        assert state.conversation_history == []

    def test_reset_state(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        config = TargetConfig(url="https://chat.example.com", protocol="browser")
        adapter = BrowserAgentAdapter(config)
        adapter._conversation.append({"role": "user", "content": "hi"})
        adapter._tool_observations.append({"tool": "test"})
        adapter.reset_state()
        assert adapter._conversation == []
        assert adapter._tool_observations == []

    def test_observe_tool_call(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        config = TargetConfig(url="https://chat.example.com", protocol="browser")
        adapter = BrowserAgentAdapter(config)
        adapter.observe_tool_call("search", {"q": "test"}, "results")
        assert len(adapter._tool_observations) == 1
        assert adapter._tool_observations[0]["tool"] == "search"


# ──────────────────────────────────────────────────────────────────────
# Network extraction helpers
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestNetworkExtraction:
    """Tests for try_extract_content and extract_tool_calls."""

    def test_extract_openai_content(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import try_extract_content

        body: dict[str, Any] = {
            "choices": [{"message": {"content": "Hello! How can I help?"}}],
        }
        assert try_extract_content(body) == "Hello! How can I help?"

    def test_extract_anthropic_content(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import try_extract_content

        body: dict[str, Any] = {
            "content": [{"type": "text", "text": "I can assist with that."}],
        }
        assert try_extract_content(body) == "I can assist with that."

    def test_extract_generic_response(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import try_extract_content

        body: dict[str, Any] = {"response": "Here is your answer."}
        assert try_extract_content(body) == "Here is your answer."

    def test_extract_with_explicit_path(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import try_extract_content

        body: dict[str, Any] = {"data": {"result": {"text": "Found it!"}}}
        assert try_extract_content(body, "data.result.text") == "Found it!"

    def test_extract_returns_none_for_empty(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import try_extract_content

        assert try_extract_content({}) is None
        assert try_extract_content({"unrelated": 42}) is None

    def test_extract_openai_tool_calls(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import extract_tool_calls

        body: dict[str, Any] = {
            "choices": [
                {
                    "message": {
                        "content": "Let me search that.",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "web_search",
                                    "arguments": '{"query": "test"}',
                                }
                            }
                        ],
                    }
                }
            ],
        }
        tools = extract_tool_calls(body)
        assert len(tools) == 1
        assert tools[0]["tool"] == "web_search"
        assert tools[0]["input"] == {"query": "test"}

    def test_extract_anthropic_tool_calls(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import extract_tool_calls

        body: dict[str, Any] = {
            "content": [
                {"type": "text", "text": "Using the calculator."},
                {"type": "tool_use", "name": "calculator", "input": {"expr": "2+2"}},
            ],
        }
        tools = extract_tool_calls(body)
        assert len(tools) == 1
        assert tools[0]["tool"] == "calculator"
        assert tools[0]["input"] == {"expr": "2+2"}

    def test_extract_generic_tool_calls(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import extract_tool_calls

        body: dict[str, Any] = {
            "tool_calls": [
                {"name": "read_file", "arguments": {"path": "/etc/hosts"}},
            ],
        }
        tools = extract_tool_calls(body)
        assert len(tools) == 1
        assert tools[0]["tool"] == "read_file"

    def test_extract_no_tool_calls(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import extract_tool_calls

        body: dict[str, Any] = {"choices": [{"message": {"content": "No tools used."}}]}
        tools = extract_tool_calls(body)
        assert tools == []


# ──────────────────────────────────────────────────────────────────────
# URL matching
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestUrlMatching:
    """Tests for the glob-style URL matching."""

    def test_matches_double_star(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        assert BrowserAgentAdapter._url_matches_pattern(
            "https://example.com/api/v1/chat/completions",
            "**/api/v1/chat/**",
        )

    def test_no_match(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        assert not BrowserAgentAdapter._url_matches_pattern(
            "https://example.com/health",
            "**/api/chat/**",
        )

    def test_matches_exact_path(self) -> None:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        assert BrowserAgentAdapter._url_matches_pattern(
            "https://example.com/v1/chat/completions",
            "**/v1/chat/completions",
        )


# ──────────────────────────────────────────────────────────────────────
# Adapter invoke with mocked Playwright
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBrowserAdapterInvoke:
    """Tests for invoke() with mocked Playwright internals."""

    def _make_adapter(self) -> Any:
        from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

        config = TargetConfig(
            url="https://chat.example.com",
            protocol="browser",
            browser=BrowserConfig(
                api_url_pattern="**/api/chat",
                response_json_path="choices.0.message.content",
            ),
        )
        adapter = BrowserAgentAdapter(config)

        # Pre-initialize with mocks (skip real Playwright)
        mock_page = AsyncMock()
        mock_page.query_selector_all = AsyncMock(return_value=[])
        mock_page.wait_for_selector = AsyncMock(return_value=MagicMock())
        mock_page.wait_for_timeout = AsyncMock()

        mock_input = AsyncMock()
        mock_page.wait_for_selector.return_value = mock_input

        adapter._page = mock_page
        adapter._session_id = "test-session"
        adapter._detected_api_pattern = "**/api/chat"

        return adapter

    async def test_invoke_with_intercepted_response(self) -> None:
        adapter = self._make_adapter()

        # Pre-populate intercepted response
        async def fake_submit(*args: Any, **kwargs: Any) -> None:
            adapter._intercepted_responses.append(
                {
                    "choices": [{"message": {"content": "I can help with that!"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
                }
            )

        adapter._type_and_submit = fake_submit  # type: ignore[assignment]

        response = await adapter.invoke("Hello")
        assert response.content == "I can help with that!"
        assert response.metadata["extraction_mode"] == "network"
        assert response.prompt_tokens == 10
        assert response.completion_tokens == 8

    async def test_invoke_dom_fallback(self) -> None:
        adapter = self._make_adapter()
        adapter._use_dom_fallback = True
        adapter._detected_api_pattern = None

        # Mock DOM elements
        mock_el = AsyncMock()
        mock_el.inner_text = AsyncMock(return_value="Hello from the chatbot!")
        adapter._page.query_selector_all = AsyncMock(return_value=[mock_el])
        adapter._page.evaluate = AsyncMock()
        adapter._type_and_submit = AsyncMock()  # type: ignore[assignment]

        response = await adapter.invoke("Hi")
        assert response.content == "Hello from the chatbot!"
        assert response.metadata["extraction_mode"] == "dom"
        assert response.tool_calls == []

    async def test_invoke_tracks_conversation(self) -> None:
        adapter = self._make_adapter()

        async def fake_submit(*args: Any, **kwargs: Any) -> None:
            adapter._intercepted_responses.append(
                {
                    "choices": [{"message": {"content": "Response"}}],
                }
            )

        adapter._type_and_submit = fake_submit  # type: ignore[assignment]

        await adapter.invoke("Message 1")
        assert len(adapter._conversation) == 2
        assert adapter._conversation[0] == {"role": "user", "content": "Message 1"}
        assert adapter._conversation[1] == {"role": "assistant", "content": "Response"}

    async def test_close_cleans_up(self) -> None:
        adapter = self._make_adapter()
        adapter._context = AsyncMock()
        adapter._browser = AsyncMock()
        adapter._playwright = AsyncMock()

        await adapter.close()
        assert adapter._page is None
        assert adapter._context is None
        assert adapter._browser is None
        assert adapter._playwright is None
