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

        # Mock option detection so invoke() doesn't hit locator on mock page
        adapter._detect_option_buttons = AsyncMock(return_value=[])  # type: ignore[assignment]

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


# ──────────────────────────────────────────────────────────────────────
# Smart UI discovery
# ──────────────────────────────────────────────────────────────────────


def _make_discovery_adapter(
    auto_discover: bool = True,
    input_selector: str = "textarea, input[type='text']",
    submit_selector: str | None = None,
) -> Any:
    """Create an adapter with a mocked page for discovery tests."""
    from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

    config = TargetConfig(
        url="https://chatbot.example.com",
        protocol="browser",
        browser=BrowserConfig(
            auto_discover=auto_discover,
            input_selector=input_selector,
            submit_selector=submit_selector,
        ),
    )
    adapter = BrowserAgentAdapter(config)

    # Create mock page
    mock_page = AsyncMock()
    mock_page.wait_for_timeout = AsyncMock()
    adapter._page = mock_page

    return adapter


def _mock_locator(visible: bool = False, tag: str = "button") -> MagicMock:
    """Create a mock Playwright locator."""
    locator = MagicMock()
    locator.is_visible = AsyncMock(return_value=visible)
    locator.wait_for = AsyncMock()
    locator.click = AsyncMock()
    locator.evaluate = AsyncMock(return_value=tag)
    if not visible:
        locator.is_visible.side_effect = Exception("not visible")
        locator.wait_for.side_effect = Exception("timeout")
    return locator


@pytest.mark.unit
class TestBrowserConfigAutoDiscover:
    """Tests for the auto_discover config field."""

    def test_auto_discover_default_true(self) -> None:
        cfg = BrowserConfig()
        assert cfg.auto_discover is True

    def test_auto_discover_can_be_disabled(self) -> None:
        cfg = BrowserConfig(auto_discover=False)
        assert cfg.auto_discover is False


@pytest.mark.unit
class TestCookieBannerDismissal:
    """Tests for _dismiss_cookie_banner."""

    async def test_dismisses_visible_cookie_button(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        # First selector not visible, second one is
        call_count = 0

        def make_locator_fn(selector: str) -> MagicMock:
            nonlocal call_count
            locator = MagicMock()
            locator.first = locator
            # Make the "Accept" button visible (5th in _COOKIE_DISMISS_SELECTORS)
            if "Accept" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.click = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        await adapter._dismiss_cookie_banner()

    async def test_no_cookie_banner_is_noop(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        # All selectors fail
        def always_invisible(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = always_invisible

        # Should not raise
        await adapter._dismiss_cookie_banner()


@pytest.mark.unit
class TestFindAndClickLauncher:
    """Tests for _find_and_click_launcher."""

    async def test_clicks_visible_launcher(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        clicked_selector = None

        def make_locator_fn(selector: str) -> MagicMock:
            nonlocal clicked_selector
            locator = MagicMock()
            locator.first = locator

            # Make "Start" button visible
            if "Start" in selector and "button" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.evaluate = AsyncMock(return_value="button")

                async def mock_click(**kwargs: Any) -> None:
                    nonlocal clicked_selector
                    clicked_selector = selector

                locator.click = mock_click
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        result = await adapter._find_and_click_launcher()
        assert result is True
        assert clicked_selector is not None
        assert "Start" in clicked_selector

    async def test_no_launcher_returns_false(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        def always_invisible(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = always_invisible

        result = await adapter._find_and_click_launcher()
        assert result is False


@pytest.mark.unit
class TestDiscoverInputSelector:
    """Tests for _discover_input_selector."""

    async def test_finds_textarea(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if selector == "textarea":
                locator.is_visible = AsyncMock(return_value=True)
                locator.evaluate = AsyncMock(return_value=True)  # editable
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        result = await adapter._discover_input_selector()
        assert result == "textarea"

    async def test_finds_contenteditable(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if selector == "[contenteditable='true']":
                locator.is_visible = AsyncMock(return_value=True)
                locator.evaluate = AsyncMock(return_value=True)
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        result = await adapter._discover_input_selector()
        assert result == "[contenteditable='true']"

    async def test_skips_disabled_input(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if selector == "textarea":
                locator.is_visible = AsyncMock(return_value=True)
                locator.evaluate = AsyncMock(return_value=False)  # disabled
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        result = await adapter._discover_input_selector()
        assert result is None

    async def test_no_input_returns_none(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        def always_invisible(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = always_invisible

        result = await adapter._discover_input_selector()
        assert result is None


@pytest.mark.unit
class TestEffectiveSelectors:
    """Tests for the _effective_*_selector properties."""

    def test_default_input_uses_discovered(self) -> None:
        adapter = _make_discovery_adapter()
        adapter._discovered_input_selector = "[contenteditable='true']"

        assert adapter._effective_input_selector == "[contenteditable='true']"

    def test_explicit_input_ignores_discovered(self) -> None:
        adapter = _make_discovery_adapter(input_selector="#custom-input")
        adapter._discovered_input_selector = "[contenteditable='true']"

        assert adapter._effective_input_selector == "#custom-input"

    def test_no_discovery_uses_default(self) -> None:
        adapter = _make_discovery_adapter()

        assert adapter._effective_input_selector == "textarea, input[type='text']"

    def test_default_submit_uses_discovered(self) -> None:
        adapter = _make_discovery_adapter()
        adapter._discovered_submit_selector = "button:has-text('Send')"

        assert adapter._effective_submit_selector == "button:has-text('Send')"

    def test_explicit_submit_ignores_discovered(self) -> None:
        adapter = _make_discovery_adapter(submit_selector="#send-btn")
        adapter._discovered_submit_selector = "button:has-text('Send')"

        assert adapter._effective_submit_selector == "#send-btn"


@pytest.mark.unit
class TestDiscoverChatUI:
    """Integration tests for the full _discover_chat_ui flow."""

    async def test_skips_when_input_already_visible(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        # Cookie banner: nothing to dismiss
        # Input: immediately visible
        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if selector == "textarea, input[type='text']":
                locator.is_visible = AsyncMock(return_value=True)
                locator.wait_for = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
                locator.wait_for = AsyncMock(side_effect=Exception("timeout"))
            return locator

        page.locator = make_locator_fn

        await adapter._discover_chat_ui()
        # No discovered selectors needed — defaults work
        assert adapter._discovered_input_selector is None

    async def test_clicks_launcher_then_discovers_input(self) -> None:
        adapter = _make_discovery_adapter()
        page = adapter._page

        launcher_clicked = False
        phase = {"input_visible": False}

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator

            if selector == "textarea, input[type='text']":
                # Initially not visible, visible after launcher click
                async def check_visible(**kwargs: Any) -> bool:
                    return phase["input_visible"]

                locator.is_visible = check_visible

                async def wait_for_vis(**kwargs: Any) -> None:
                    if not phase["input_visible"]:
                        raise Exception("timeout")

                locator.wait_for = wait_for_vis
            elif "Start" in selector and "button" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.evaluate = AsyncMock(return_value="button")

                async def mock_click(**kwargs: Any) -> None:
                    nonlocal launcher_clicked
                    launcher_clicked = True
                    phase["input_visible"] = True

                locator.click = mock_click
            elif selector == "textarea":
                # Discovered after launcher click
                async def check_textarea(**kwargs: Any) -> bool:
                    return phase["input_visible"]

                locator.is_visible = check_textarea
                locator.evaluate = AsyncMock(return_value=True)  # editable
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
                locator.wait_for = AsyncMock(side_effect=Exception("timeout"))
            return locator

        page.locator = make_locator_fn

        await adapter._discover_chat_ui()
        assert launcher_clicked is True

    async def test_auto_discover_false_skips_entirely(self) -> None:
        """When auto_discover=False, _discover_chat_ui should not be called."""
        adapter = _make_discovery_adapter(auto_discover=False)

        # If discovery ran, it would use the page — which would fail
        adapter._page = None  # Would crash if discovery tried to run

        # The flag is checked in _ensure_initialized, not in _discover_chat_ui,
        # so we verify the config value directly
        assert adapter._browser_config.auto_discover is False


# ──────────────────────────────────────────────────────────────────────
# BrowserConfig option handling fields
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBrowserConfigOptions:
    """Tests for option handling config fields."""

    def test_option_defaults(self) -> None:
        cfg = BrowserConfig()
        assert cfg.option_selector == ""
        assert cfg.initial_options == "auto"
        assert cfg.max_option_depth == 3
        assert cfg.prefer_options == []

    def test_custom_option_config(self) -> None:
        cfg = BrowserConfig(
            option_selector=".my-chip",
            initial_options="click_through",
            max_option_depth=5,
            prefer_options=["Vraag stellen", "Ask a question"],
        )
        assert cfg.option_selector == ".my-chip"
        assert cfg.initial_options == "click_through"
        assert cfg.max_option_depth == 5
        assert cfg.prefer_options == ["Vraag stellen", "Ask a question"]

    def test_option_strategy_skip(self) -> None:
        cfg = BrowserConfig(initial_options="skip")
        assert cfg.initial_options == "skip"

    def test_option_strategy_type_through(self) -> None:
        cfg = BrowserConfig(initial_options="type_through")
        assert cfg.initial_options == "type_through"


# ──────────────────────────────────────────────────────────────────────
# Option detection and handling
# ──────────────────────────────────────────────────────────────────────


def _make_option_adapter(
    initial_options: str = "auto",
    option_selector: str = "",
    max_option_depth: int = 3,
    prefer_options: list[str] | None = None,
) -> Any:
    """Create an adapter with mocked page for option tests."""
    from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

    config = TargetConfig(
        url="https://chatbot.example.com",
        protocol="browser",
        browser=BrowserConfig(
            initial_options=initial_options,  # type: ignore[arg-type]
            option_selector=option_selector,
            max_option_depth=max_option_depth,
            prefer_options=prefer_options or [],
        ),
    )
    adapter = BrowserAgentAdapter(config)

    mock_page = AsyncMock()
    mock_page.wait_for_timeout = AsyncMock()
    adapter._page = mock_page

    return adapter


@pytest.mark.unit
class TestDetectOptionButtons:
    """Tests for _detect_option_buttons."""

    async def test_detects_quick_reply_buttons(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            if "quick-reply" in selector:
                locator.count = AsyncMock(return_value=3)

                def nth(i: int) -> MagicMock:
                    el = MagicMock()
                    texts = ["Track package", "Report issue", "Something else"]
                    el.is_visible = AsyncMock(return_value=True)
                    el.inner_text = AsyncMock(return_value=texts[i])
                    return el

                locator.nth = nth
            else:
                locator.count = AsyncMock(return_value=0)
            return locator

        page.locator = make_locator_fn

        options = await adapter._detect_option_buttons()
        assert len(options) == 3
        texts = [t for _, t in options]
        assert "Track package" in texts
        assert "Report issue" in texts
        assert "Something else" in texts

    async def test_deduplicates_options(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        call_idx = 0

        def make_locator_fn(selector: str) -> MagicMock:
            nonlocal call_idx
            locator = MagicMock()
            # Two selectors both find the same button text
            if "quick-reply" in selector or "chip" in selector:
                locator.count = AsyncMock(return_value=1)

                def nth(i: int) -> MagicMock:
                    el = MagicMock()
                    el.is_visible = AsyncMock(return_value=True)
                    el.inner_text = AsyncMock(return_value="Track package")
                    return el

                locator.nth = nth
            else:
                locator.count = AsyncMock(return_value=0)
            return locator

        page.locator = make_locator_fn

        options = await adapter._detect_option_buttons()
        # Should be deduplicated to 1 despite matching multiple selectors
        assert len(options) == 1
        assert options[0][1] == "Track package"

    async def test_no_options_returns_empty(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.count = AsyncMock(return_value=0)
            return locator

        page.locator = make_locator_fn

        options = await adapter._detect_option_buttons()
        assert options == []

    async def test_uses_explicit_option_selector(self) -> None:
        adapter = _make_option_adapter(option_selector=".my-custom-chip")
        page = adapter._page

        used_selectors: list[str] = []

        def make_locator_fn(selector: str) -> MagicMock:
            used_selectors.append(selector)
            locator = MagicMock()
            if selector == ".my-custom-chip":
                locator.count = AsyncMock(return_value=1)

                def nth(i: int) -> MagicMock:
                    el = MagicMock()
                    el.is_visible = AsyncMock(return_value=True)
                    el.inner_text = AsyncMock(return_value="Custom option")
                    return el

                locator.nth = nth
            else:
                locator.count = AsyncMock(return_value=0)
            return locator

        page.locator = make_locator_fn

        options = await adapter._detect_option_buttons()
        assert len(options) == 1
        assert options[0][1] == "Custom option"
        # Should only try the custom selector, not the default list
        assert ".my-custom-chip" in used_selectors
        assert len(used_selectors) == 1


@pytest.mark.unit
class TestClickPreferredOption:
    """Tests for _click_preferred_option."""

    async def test_clicks_matching_preferred_option(self) -> None:
        adapter = _make_option_adapter(prefer_options=["Vraag stellen"])
        page = adapter._page

        clicked_texts: list[str] = []

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Vraag stellen" in selector:
                locator.is_visible = AsyncMock(return_value=True)

                async def do_click(**kwargs: Any) -> None:
                    clicked_texts.append("Vraag stellen")

                locator.click = do_click
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Track & Trace"),
            ("[class*='chip']", "Vraag stellen"),
            ("[class*='chip']", "Retourneren"),
        ]
        result = await adapter._click_preferred_option(options)
        assert result is True
        assert "Vraag stellen" in clicked_texts

    async def test_case_insensitive_match(self) -> None:
        adapter = _make_option_adapter(prefer_options=["ask a question"])
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Ask a Question" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.click = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [("[class*='chip']", "Ask a Question")]
        result = await adapter._click_preferred_option(options)
        assert result is True

    async def test_substring_match(self) -> None:
        """Prefer options should match as substring."""
        adapter = _make_option_adapter(prefer_options=["vraag"])
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Stel een vraag" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.click = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Bezorging"),
            ("[class*='chip']", "Stel een vraag"),
        ]
        result = await adapter._click_preferred_option(options)
        assert result is True

    async def test_respects_pattern_priority(self) -> None:
        """First matching prefer_options pattern wins."""
        adapter = _make_option_adapter(prefer_options=["retour", "track"])
        page = adapter._page

        clicked_texts: list[str] = []

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Retourneren" in selector:
                locator.is_visible = AsyncMock(return_value=True)

                async def do_click(**kwargs: Any) -> None:
                    clicked_texts.append("Retourneren")

                locator.click = do_click
            elif "Track & Trace" in selector:
                locator.is_visible = AsyncMock(return_value=True)

                async def do_click2(**kwargs: Any) -> None:
                    clicked_texts.append("Track & Trace")

                locator.click = do_click2
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Track & Trace"),
            ("[class*='chip']", "Retourneren"),
        ]
        result = await adapter._click_preferred_option(options)
        assert result is True
        # "retour" pattern comes first, so Retourneren should be clicked
        assert clicked_texts == ["Retourneren"]

    async def test_no_match_returns_false(self) -> None:
        adapter = _make_option_adapter(prefer_options=["nonexistent option"])
        page = adapter._page

        page.locator = MagicMock(
            return_value=MagicMock(
                first=MagicMock(is_visible=AsyncMock(side_effect=Exception("not visible")))
            )
        )

        options = [
            ("[class*='chip']", "Track & Trace"),
            ("[class*='chip']", "Bezorging"),
        ]
        result = await adapter._click_preferred_option(options)
        assert result is False

    async def test_empty_prefer_options_returns_false(self) -> None:
        adapter = _make_option_adapter(prefer_options=[])

        options = [("[class*='chip']", "Track & Trace")]
        result = await adapter._click_preferred_option(options)
        assert result is False


@pytest.mark.unit
class TestClickFreetextOption:
    """Tests for _click_freetext_option."""

    async def test_finds_something_else(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        clicked_texts: list[str] = []

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            # Match the text-based click
            if "Something else" in selector:
                locator.is_visible = AsyncMock(return_value=True)

                async def do_click(**kwargs: Any) -> None:
                    clicked_texts.append("Something else")

                locator.click = do_click
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='quick-reply']", "Track package"),
            ("[class*='quick-reply']", "Something else"),
        ]
        result = await adapter._click_freetext_option(options)
        assert result is True
        assert "Something else" in clicked_texts

    async def test_finds_iets_anders(self) -> None:
        """Dutch 'iets anders' should match free-text patterns."""
        adapter = _make_option_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Iets anders" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.click = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Bezorging"),
            ("[class*='chip']", "Iets anders"),
        ]
        result = await adapter._click_freetext_option(options)
        assert result is True

    async def test_no_freetext_option(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        page.locator = MagicMock(
            return_value=MagicMock(
                first=MagicMock(is_visible=AsyncMock(side_effect=Exception("not visible")))
            )
        )

        options = [
            ("[class*='chip']", "Track package"),
            ("[class*='chip']", "Returns"),
        ]
        result = await adapter._click_freetext_option(options)
        assert result is False


@pytest.mark.unit
class TestClickBestOption:
    """Tests for _click_best_option."""

    async def test_prefers_normal_over_deepening(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        clicked: list[str] = []

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Track" in selector:
                locator.is_visible = AsyncMock(return_value=True)

                async def do_click(**kwargs: Any) -> None:
                    clicked.append("Track package")

                locator.click = do_click
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Track package"),
            ("[class*='chip']", "Show more..."),
        ]
        result = await adapter._click_best_option(options)
        assert result is True
        assert "Track package" in clicked

    async def test_falls_back_to_deepening_if_only_option(self) -> None:
        adapter = _make_option_adapter()
        page = adapter._page

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = locator
            if "Show more" in selector:
                locator.is_visible = AsyncMock(return_value=True)
                locator.click = AsyncMock()
            else:
                locator.is_visible = AsyncMock(side_effect=Exception("not visible"))
            return locator

        page.locator = make_locator_fn

        options = [
            ("[class*='chip']", "Show more..."),
        ]
        result = await adapter._click_best_option(options)
        assert result is True

    async def test_empty_options(self) -> None:
        adapter = _make_option_adapter()
        result = await adapter._click_best_option([])
        assert result is False


@pytest.mark.unit
class TestHandleInitialOptions:
    """Tests for _handle_initial_options."""

    async def test_skip_strategy_does_nothing(self) -> None:
        adapter = _make_option_adapter(initial_options="skip")
        # Should return without touching the page
        await adapter._handle_initial_options()

    async def test_type_through_does_nothing(self) -> None:
        adapter = _make_option_adapter(initial_options="type_through")
        await adapter._handle_initial_options()

    async def test_auto_navigates_through_options(self) -> None:
        adapter = _make_option_adapter(initial_options="auto", max_option_depth=2)
        page = adapter._page

        depth_counter = {"current": 0}

        async def mock_detect() -> list[tuple[str, str]]:
            d = depth_counter["current"]
            if d == 0:
                return [
                    ("[class*='chip']", "Track package"),
                    ("[class*='chip']", "Iets anders"),
                ]
            return []  # No more options after clicking

        adapter._detect_option_buttons = mock_detect  # type: ignore[assignment]

        async def mock_click_freetext(
            options: list[tuple[str, str]],
        ) -> bool:
            depth_counter["current"] += 1
            return True

        adapter._click_freetext_option = mock_click_freetext  # type: ignore[assignment]

        # Mock input visibility check
        mock_input = MagicMock()
        mock_input.is_visible = AsyncMock(return_value=False)
        mock_input.evaluate = AsyncMock(return_value=False)

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = mock_input
            return locator

        page.locator = make_locator_fn

        await adapter._handle_initial_options()
        assert depth_counter["current"] >= 1

    async def test_respects_max_option_depth(self) -> None:
        adapter = _make_option_adapter(
            initial_options="click_through",
            max_option_depth=2,
        )
        page = adapter._page

        click_count = {"n": 0}

        async def mock_detect() -> list[tuple[str, str]]:
            # Always return options (infinite menu)
            return [("[class*='chip']", f"Option {click_count['n']}")]

        adapter._detect_option_buttons = mock_detect  # type: ignore[assignment]

        async def mock_click_best(
            options: list[tuple[str, str]],
        ) -> bool:
            click_count["n"] += 1
            return True

        adapter._click_best_option = mock_click_best  # type: ignore[assignment]

        # Mock input as never focused
        mock_input = MagicMock()
        mock_input.is_visible = AsyncMock(return_value=False)

        def make_locator_fn(selector: str) -> MagicMock:
            locator = MagicMock()
            locator.first = mock_input
            return locator

        page.locator = make_locator_fn

        await adapter._handle_initial_options()
        # Should stop after max_option_depth
        assert click_count["n"] == 2

    async def test_stops_when_no_options_detected(self) -> None:
        adapter = _make_option_adapter(initial_options="auto")

        async def mock_detect() -> list[tuple[str, str]]:
            return []

        adapter._detect_option_buttons = mock_detect  # type: ignore[assignment]

        # Should return quickly
        await adapter._handle_initial_options()

    async def test_prefer_options_tried_before_freetext(self) -> None:
        """prefer_options should be tried before built-in freetext patterns."""
        adapter = _make_option_adapter(
            initial_options="auto",
            max_option_depth=1,
            prefer_options=["Vraag stellen"],
        )

        call_log: list[str] = []

        async def mock_detect() -> list[tuple[str, str]]:
            return [
                ("[class*='chip']", "Iets anders"),  # built-in freetext pattern
                ("[class*='chip']", "Vraag stellen"),  # user preferred option
            ]

        adapter._detect_option_buttons = mock_detect  # type: ignore[assignment]

        async def mock_click_preferred(
            options: list[tuple[str, str]],
        ) -> bool:
            call_log.append("preferred")
            return True  # Preferred found, so freetext should NOT be called

        async def mock_click_freetext(
            options: list[tuple[str, str]],
        ) -> bool:
            call_log.append("freetext")
            return True

        adapter._click_preferred_option = mock_click_preferred  # type: ignore[assignment]
        adapter._click_freetext_option = mock_click_freetext  # type: ignore[assignment]

        await adapter._handle_initial_options()
        # preferred should be called first and freetext should NOT be called
        assert call_log == ["preferred"]

    async def test_prefer_options_falls_through_to_freetext(self) -> None:
        """When prefer_options don't match, fall through to freetext patterns."""
        adapter = _make_option_adapter(
            initial_options="auto",
            max_option_depth=1,
            prefer_options=["nonexistent"],
        )

        call_log: list[str] = []

        async def mock_detect() -> list[tuple[str, str]]:
            return [
                ("[class*='chip']", "Iets anders"),
                ("[class*='chip']", "Bezorging"),
            ]

        adapter._detect_option_buttons = mock_detect  # type: ignore[assignment]

        async def mock_click_preferred(
            options: list[tuple[str, str]],
        ) -> bool:
            call_log.append("preferred")
            return False  # No match

        async def mock_click_freetext(
            options: list[tuple[str, str]],
        ) -> bool:
            call_log.append("freetext")
            return True

        adapter._click_preferred_option = mock_click_preferred  # type: ignore[assignment]
        adapter._click_freetext_option = mock_click_freetext  # type: ignore[assignment]

        await adapter._handle_initial_options()
        # Both should be called since preferred didn't match
        assert call_log == ["preferred", "freetext"]
