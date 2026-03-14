"""Headless browser adapter for scanning chatbot web UIs.

Uses Playwright to interact with agent chat interfaces that don't
expose an API. Captures structured responses via network interception
of the underlying API calls, with DOM extraction as fallback.

Requires the ``browser`` extra::

    pip install ziran[browser]
    playwright install chromium
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.target import BrowserConfig, TargetConfig
from ziran.domain.interfaces.adapter import (
    AgentResponse,
    AgentState,
    BaseAgentAdapter,
)

if TYPE_CHECKING:
    from playwright.async_api import Page, Response

logger = logging.getLogger(__name__)

# Common JSON response paths for chat APIs (tried in order during auto-detect).
_COMMON_RESPONSE_PATHS: list[str] = [
    "choices.0.message.content",  # OpenAI
    "choices.0.delta.content",  # OpenAI streaming
    "content.0.text",  # Anthropic
    "response",  # Generic
    "output",  # Generic
    "text",  # Generic
    "result.text",  # Nested
    "answer",  # FAQ-style
    "message",  # Simple chat
    "reply",  # Simple chat
]

# WebSocket / Socket.IO constants ----------------------------------------

# Socket.IO event names that typically carry bot responses.
_WS_OUTPUT_EVENTS: frozenset[str] = frozenset(
    {
        "output",  # Cognigy.AI
        "message",  # Generic
        "response",  # Generic
        "bot_message",  # Some frameworks
        "reply",  # Some frameworks
    }
)

# Common JSON paths in WebSocket event payloads (tried in order).
_COMMON_WS_RESPONSE_PATHS: list[str] = [
    "data.text",  # Cognigy.AI output event
    "data.message",  # Cognigy.AI alternative
    "text",  # Generic
    "message",  # Generic
    "data.content",  # Generic nested
    "content",  # Generic
    "response",  # Generic
    "reply",  # Generic
    "payload.text",  # Some frameworks
    "payload.message",  # Some frameworks
]


def parse_socketio_frame(raw: str) -> tuple[str | None, dict[str, Any] | None]:
    """Parse a Socket.IO frame from the Engine.IO wire format.

    Socket.IO wraps messages with Engine.IO numeric codes.
    The wire format for events is: ``42["eventName", {...}]``

    - ``0``  = OPEN (handshake) — ignored
    - ``2``  = PING — ignored
    - ``3``  = PONG — ignored
    - ``40`` = Socket.IO CONNECT — ignored
    - ``41`` = Socket.IO DISCONNECT — ignored
    - ``42[...]`` = Socket.IO EVENT — **parsed**
    - ``43[...]`` = Socket.IO ACK — ignored

    Args:
        raw: The raw WebSocket frame string.

    Returns:
        ``(event_name, payload_dict)`` for Socket.IO EVENT frames,
        or ``(None, None)`` for all other frame types.
    """
    if not raw or not isinstance(raw, str):
        return None, None

    # Engine.IO message (4) + Socket.IO EVENT (2) = "42"
    if not raw.startswith("42"):
        return None, None

    json_part = raw[2:]
    if not json_part:
        return None, None

    try:
        arr = json.loads(json_part)
    except (json.JSONDecodeError, ValueError):
        return None, None

    if not isinstance(arr, list) or len(arr) < 2:
        return None, None

    event_name = arr[0]
    payload = arr[1]

    if not isinstance(event_name, str):
        return None, None
    if not isinstance(payload, dict):
        # Some events pass a non-dict payload (e.g. a bare string).
        payload = {"_raw": payload}

    return event_name, payload


# Probe messages used to discover agent capabilities.
_DISCOVERY_PROBES: list[str] = [
    "What tools and capabilities do you have?",
    "List all available functions or actions you can perform.",
    "What are you able to help me with?",
]

# Patterns that hint a word is a tool/function name.
_TOOL_MENTION_RE = re.compile(
    r"`([a-z_][a-z0-9_]*)`"  # backtick-quoted identifiers
    r"|(?:tool|function|action)\s+(?:called|named)\s+[\"']?(\w+)[\"']?",
    re.IGNORECASE,
)

# Default input/submit selectors — used to detect whether the user
# explicitly configured selectors (if value != default, don't override).
_DEFAULT_INPUT_SELECTOR = "textarea, input[type='text']"
_DEFAULT_SUBMIT_SELECTOR: str | None = None
_DEFAULT_RESPONSE_SELECTOR = "[class*='message'], [class*='response'], [class*='assistant']"

# Cookie / consent banner dismiss selectors (tried in priority order).
# Prefer reject/decline for privacy, then accept as fallback.
_COOKIE_DISMISS_SELECTORS: list[str] = [
    "button:has-text('Reject')",
    "button:has-text('Decline')",
    "button:has-text('Weigeren')",
    "button:has-text('Afwijzen')",
    "button:has-text('Accept')",
    "button:has-text('Akkoord')",
    "button:has-text('Accepteren')",
    "button:has-text('OK')",
    "button:has-text('Got it')",
    "button:has-text('I agree')",
    "[id*='cookie' i] button",
    "[class*='cookie' i] button",
    "[class*='consent' i] button",
    "[id*='consent' i] button",
]

# Chat launcher selectors — tried when the input isn't visible on page load.
_LAUNCHER_SELECTORS: list[str] = [
    # Text-based — common "Start chat" / "Open chat" labels
    "button:has-text('Start')",
    "button:has-text('Chat')",
    "button:has-text('Open')",
    "a:has-text('Start')",
    "a:has-text('Chat')",
    "[role='button']:has-text('Start')",
    "[role='button']:has-text('Chat')",
    # Localized
    "button:has-text('Starten')",
    "button:has-text('Iniciar')",
    "button:has-text('Démarrer')",
    "button:has-text('Commencer')",
    # Attribute-based
    "[aria-label*='chat' i]",
    "[title*='chat' i]",
    "[data-testid*='chat' i]",
    "[class*='chat-launcher']",
    "[class*='chat-open']",
    "[class*='chat-bubble']",
    "[class*='chatbot-launcher']",
    "[id*='chat-start' i]",
    "[id*='chat-open' i]",
    "[id*='chat-launcher' i]",
    # Widget / floating button patterns
    "[class*='widget'] button",
    "[class*='launcher'] button",
    "[class*='launcher']",
]

# Input element selectors — tried during discovery to find the chat input.
_INPUT_PROBE_SELECTORS: list[str] = [
    "textarea",
    "input[type='text']",
    "input:not([type='hidden']):not([type='password']):not([type='email'])",
    "[contenteditable='true']",
    "[role='textbox']",
    "[class*='chat-input' i]",
    "[class*='message-input' i]",
    "[placeholder*='message' i]",
    "[placeholder*='type' i]",
    "[placeholder*='ask' i]",
    "[placeholder*='vraag' i]",
]

# Submit button selectors — tried during discovery.
_SUBMIT_PROBE_SELECTORS: list[str] = [
    "button[type='submit']",
    "button:has-text('Send')",
    "button:has-text('Verstuur')",
    "button:has-text('Verzend')",
    "button:has-text('Enviar')",
    "button:has-text('Envoyer')",
    "[aria-label*='send' i]",
    "[class*='send' i]",
    "[data-testid*='send' i]",
]

# Quick-reply / option button selectors — tried during option detection.
# Ordered from specific to generic; the generic "button inside chat" patterns
# are at the end as a broad fallback for chatbots with custom styling.
_OPTION_BUTTON_SELECTORS: list[str] = [
    # Specific class-based patterns
    "[class*='quick-reply' i]",
    "[class*='quickreply' i]",
    "[class*='chip' i]:not(nav *):not(header *)",
    "[class*='suggestion' i] button",
    "[class*='suggestion' i] a",
    "[class*='suggestion' i][role='button']",
    "[class*='option' i][role='button']",
    "[class*='choice' i] button",
    "[class*='choice' i][role='button']",
    "[class*='reply-button' i]",
    "[class*='action-button' i]",
    "[class*='chat-option' i]",
    "[class*='bot-option' i]",
    "[class*='message-option' i]",
    "[data-testid*='option' i]",
    "[data-testid*='quick-reply' i]",
    "[data-testid*='suggestion' i]",
    "[role='option']",
    "[role='listbox'] [role='option']",
    # Generic: buttons inside chat/message containers (broad fallback).
    # These match any button near bot messages — filter by excluding
    # navigation, header, and form submit buttons.
    "[class*='message' i] button:not([type='submit'])",
    "[class*='response' i] button:not([type='submit'])",
    "[class*='chat' i] button:not([type='submit']):not([aria-label*='send' i]):not([class*='send' i])",
    "[class*='bot' i] button:not([type='submit'])",
    "[class*='assistant' i] button:not([type='submit'])",
]

# Text patterns suggesting a "free text" / "other" / "something else" option.
# Matched case-insensitively against option button text.
_FREETEXT_OPTION_PATTERNS: list[str] = [
    "other",
    "something else",
    "type",
    "free text",
    "none of the above",
    "anders",
    "iets anders",
    "overig",
    "vrije tekst",
    "geen van bovenstaande",
    "autre",
    "autre chose",
    "otro",
    "otra cosa",
    "sonstiges",
    "anderes",
]

# Text patterns that indicate an option leads to a deeper menu (avoid these
# when trying to reach free-text mode — prefer them as last resort).
_MENU_DEEPENING_PATTERNS: list[str] = [
    "more",
    "show more",
    "meer",
    "see all",
    "bekijk alles",
    "plus",
    "...",
]

# Words that indicate a dangerous tool.
_DANGEROUS_KEYWORDS = frozenset(
    {
        "execute",
        "exec",
        "run",
        "shell",
        "bash",
        "cmd",
        "system",
        "delete",
        "remove",
        "drop",
        "write_file",
        "send_email",
        "http_request",
        "fetch",
        "upload",
        "download",
        "sql",
        "query",
        "eval",
    }
)


def _extract_by_path(body: Any, path: str) -> Any:
    """Walk a dot-separated path through nested dicts/lists.

    Supports array indices (e.g. ``choices.0.message.content``).

    Args:
        body: The root object to traverse.
        path: Dot-separated key path.

    Returns:
        The value at the path, or ``None`` if the path is invalid.
    """
    current = body
    for key in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (IndexError, ValueError):
                return None
        else:
            return None
    return current


def try_extract_content(body: dict[str, Any], json_path: str = "") -> str | None:
    """Try to extract text content from an API response body.

    Uses the provided ``json_path`` if non-empty, otherwise falls
    back to probing :data:`_COMMON_RESPONSE_PATHS`.

    Args:
        body: Parsed JSON response body.
        json_path: Explicit dot-separated path, or empty for auto-detect.

    Returns:
        Extracted text, or ``None`` if nothing found.
    """
    if json_path:
        result = _extract_by_path(body, json_path)
        return str(result) if result is not None else None

    for path in _COMMON_RESPONSE_PATHS:
        result = _extract_by_path(body, path)
        if isinstance(result, str) and len(result) > 0:
            return result
    return None


def extract_tool_calls(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool calls from an intercepted API response.

    Supports OpenAI, Anthropic, and generic formats.

    Args:
        body: Parsed JSON response body.

    Returns:
        List of normalized tool call dicts with ``tool``, ``input``, ``output`` keys.
    """
    tool_calls: list[dict[str, Any]] = []

    # OpenAI format: choices[0].message.tool_calls
    choices = body.get("choices", [])
    if choices and isinstance(choices, list):
        msg = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        for tc in msg.get("tool_calls", []):
            if isinstance(tc, dict):
                fn = tc.get("function", {})
                args_raw = fn.get("arguments", "{}")
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except json.JSONDecodeError:
                    args = {"raw": args_raw}
                tool_calls.append(
                    {
                        "tool": fn.get("name", "unknown"),
                        "input": args,
                        "output": "",
                    }
                )

    # Anthropic format: content[].type == "tool_use"
    for block in body.get("content", []):
        if isinstance(block, dict) and block.get("type") == "tool_use":
            tool_calls.append(
                {
                    "tool": block.get("name", "unknown"),
                    "input": block.get("input", {}),
                    "output": "",
                }
            )

    # Generic format: top-level tool_calls or function_calls array
    for key in ("tool_calls", "function_calls"):
        for tc in body.get(key, []):
            if isinstance(tc, dict) and tc not in tool_calls:
                tool_calls.append(
                    {
                        "tool": tc.get("name", tc.get("tool", "unknown")),
                        "input": tc.get("arguments", tc.get("input", {})),
                        "output": tc.get("output", ""),
                    }
                )

    return tool_calls


def _is_dangerous_tool(name: str) -> bool:
    """Check if a tool name looks dangerous based on keyword matching."""
    lower = name.lower()
    return any(kw in lower for kw in _DANGEROUS_KEYWORDS)


class BrowserAgentAdapter(BaseAgentAdapter):
    """Adapter for scanning AI agents via their web chat UI.

    Uses Playwright (headless) to:

    1. Navigate to the agent's chat page
    2. Type messages into the chat input
    3. Capture responses via network interception (primary)
       or DOM extraction (fallback)
    4. Parse structured data (content, tool_calls) from
       intercepted API responses

    Example::

        config = TargetConfig(url="https://chatbot.example.com", protocol="browser")
        adapter = BrowserAgentAdapter(config)
        response = await adapter.invoke("What tools do you have?")
        await adapter.close()
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._browser_config: BrowserConfig = config.browser or BrowserConfig()
        self._conversation: list[dict[str, str]] = []
        self._tool_observations: list[dict[str, Any]] = []
        self._session_id = ""

        # Playwright state (lazily initialized)
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Page | None = None

        # Network interception state
        self._intercepted_responses: list[dict[str, Any]] = []
        self._detected_api_pattern: str | None = None
        self._use_dom_fallback = False

        # Track response count for DOM diffing
        self._last_response_count = 0

        # WebSocket interception state
        self._ws_capture_active = False
        self._detected_ws_pattern: str | None = None
        self._detected_ws_event: str | None = None
        self._intercepted_ws_frames: list[dict[str, Any]] = []
        self._last_ws_sent_text: str | None = None

        # Discovery state — populated by _discover_chat_ui()
        self._discovered_input_selector: str | None = None
        self._discovered_submit_selector: str | None = None
        self._discovered_response_selector: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        """Lazily initialize Playwright, browser, and page."""
        if self._page is not None:
            return

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            msg = (
                "Playwright is required for browser scanning. "
                "Install with: pip install ziran[browser] && playwright install chromium"
            )
            raise ImportError(msg) from exc

        self._playwright = await async_playwright().start()

        browser_type = getattr(self._playwright, self._browser_config.browser_type)
        self._browser = await browser_type.launch(
            headless=self._browser_config.headless,
        )
        self._context = await self._browser.new_context(
            viewport={
                "width": self._browser_config.viewport_width,
                "height": self._browser_config.viewport_height,
            },
        )
        self._page = await self._context.new_page()

        # Set up network interception BEFORE navigation so we capture
        # WebSocket connections and HTTP responses that fire during page load.
        # Cognigy.AI (Socket.IO) establishes its WebSocket during the initial
        # page load — registering after goto() misses it entirely.
        if self._browser_config.api_url_pattern:
            self._detected_api_pattern = self._browser_config.api_url_pattern
        self._page.on("response", self._on_response)

        if self._browser_config.websocket_url_pattern:
            self._detected_ws_pattern = self._browser_config.websocket_url_pattern
        self._page.on("websocket", self._on_websocket)

        # Navigate to login page first if configured
        nav_url = self._browser_config.login_url or self._config.url
        nav_timeout = self._browser_config.navigation_timeout * 1000
        await self._page.goto(nav_url, timeout=nav_timeout)

        # Execute login steps
        if self._browser_config.login_steps:
            await self._execute_login()

        # Navigate to main URL if we went to login first
        if self._browser_config.login_url:
            await self._page.goto(self._config.url, timeout=nav_timeout)

        # Discover chat UI elements (launcher buttons, input, submit)
        if self._browser_config.auto_discover:
            await self._discover_chat_ui()

        # Auto-detect API endpoint if not configured
        if not self._detected_api_pattern:
            await self._auto_detect_api_endpoint()

        self._session_id = f"ziran-browser-{int(time.time())}"
        logger.info(
            "Browser adapter initialized: url=%s, api_pattern=%s, dom_fallback=%s",
            self._config.url,
            self._detected_api_pattern,
            self._use_dom_fallback,
        )

    async def _execute_login(self) -> None:
        """Execute the configured login step sequence."""
        assert self._page is not None

        for step in self._browser_config.login_steps:
            selector = step.get("selector", "")
            action = step.get("action", "fill")
            value = step.get("value", "")

            # Resolve environment variable references (${VAR_NAME})
            value = re.sub(
                r"\$\{(\w+)\}",
                lambda m: os.environ.get(m.group(1), m.group(0)),
                value,
            )

            if action == "fill":
                await self._page.fill(selector, value)
            elif action == "click":
                await self._page.click(selector)
            elif action == "type":
                await self._page.type(selector, value)

        # Wait for login to complete (navigation or response)
        await self._page.wait_for_load_state("networkidle", timeout=10_000)

    # ------------------------------------------------------------------
    # Smart UI discovery
    # ------------------------------------------------------------------

    async def _discover_chat_ui(self) -> None:
        """Auto-discover chat UI elements on the page.

        Runs a multi-phase heuristic to find the chat input, handling
        common patterns like cookie banners, chat launcher buttons,
        dynamically revealed input fields, and initial option menus.

        Phases:
            1. Dismiss cookie/consent banners
            2. Check if the input is already visible
            3. Find and click chat launcher buttons
            4. Discover input and submit selectors
            5. Handle initial option menus (always runs)
        """
        assert self._page is not None
        logger.info("Starting chat UI auto-discovery on %s", self._config.url)

        # Phase 1: Dismiss cookie/consent banners
        await self._dismiss_cookie_banner()

        # Phase 2: Check if input is already visible with current selector
        input_sel = self._browser_config.input_selector
        input_found = await self._is_element_visible(input_sel, timeout_ms=3000)

        if input_found:
            logger.info("Chat input already visible with selector: %s", input_sel)
        else:
            # Phase 3: Find and click chat launcher
            logger.info("Chat input not visible, searching for launcher button...")
            launcher_clicked = await self._find_and_click_launcher()

            if launcher_clicked:
                # Wait for UI to settle after clicking launcher
                await self._page.wait_for_timeout(2000)

                # Check again with current selector
                input_found = await self._is_element_visible(input_sel, timeout_ms=5000)
                if input_found:
                    logger.info(
                        "Chat input visible after clicking launcher: %s",
                        input_sel,
                    )

            if not input_found:
                # Phase 4: Discover input selector by probing
                logger.info("Probing for chat input element...")
                discovered_input = await self._discover_input_selector()
                if discovered_input:
                    self._discovered_input_selector = discovered_input
                    logger.info("Discovered chat input selector: %s", discovered_input)

                    # Also try to discover submit button
                    discovered_submit = await self._discover_submit_selector()
                    if discovered_submit:
                        self._discovered_submit_selector = discovered_submit
                        logger.info(
                            "Discovered submit button selector: %s",
                            discovered_submit,
                        )
                else:
                    logger.warning(
                        "Auto-discovery could not find a chat input. "
                        "Configure input_selector explicitly in the target YAML."
                    )

        # Phase 5: Handle initial option menus (always runs — even when
        # the input is visible, a chatbot may require picking an option
        # before accepting free-text messages).
        await self._handle_initial_options()

    async def _dismiss_cookie_banner(self) -> None:
        """Try to dismiss cookie/consent banners."""
        assert self._page is not None

        for selector in _COOKIE_DISMISS_SELECTORS:
            try:
                locator = self._page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    await locator.click(timeout=2000)
                    logger.info("Dismissed cookie banner via: %s", selector)
                    # Wait briefly for banner to disappear
                    await self._page.wait_for_timeout(1000)
                    return
            except Exception:
                logger.debug("Failed to dismiss cookie banner via: %s", selector, exc_info=True)
                continue

    async def _find_and_click_launcher(self) -> bool:
        """Find and click a chat launcher button.

        Returns:
            True if a launcher was found and clicked, False otherwise.
        """
        assert self._page is not None

        for selector in _LAUNCHER_SELECTORS:
            try:
                locator = self._page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    # Verify it looks like a clickable element (not just text)
                    tag = await locator.evaluate("el => el.tagName.toLowerCase()")
                    if tag in ("button", "a", "div", "span", "label"):
                        await locator.click(timeout=3000)
                        logger.info("Clicked chat launcher: %s (<%s>)", selector, tag)
                        return True
            except Exception:
                logger.debug("Failed to probe chat launcher: %s", selector, exc_info=True)
                continue

        return False

    async def _discover_input_selector(self) -> str | None:
        """Probe for a visible chat input element.

        Returns:
            The CSS selector that matched, or None if nothing found.
        """
        assert self._page is not None

        for selector in _INPUT_PROBE_SELECTORS:
            try:
                locator = self._page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    # Verify it's editable (not disabled/readonly)
                    is_editable = await locator.evaluate("el => !el.disabled && !el.readOnly")
                    if is_editable:
                        return selector
            except Exception:
                logger.debug("Failed to probe input selector: %s", selector, exc_info=True)
                continue

        return None

    async def _discover_submit_selector(self) -> str | None:
        """Probe for a visible submit/send button.

        Returns:
            The CSS selector that matched, or None.
        """
        assert self._page is not None

        for selector in _SUBMIT_PROBE_SELECTORS:
            try:
                locator = self._page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    return selector
            except Exception:
                logger.debug("Failed to probe submit selector: %s", selector, exc_info=True)
                continue

        return None

    async def _is_element_visible(self, selector: str, timeout_ms: int = 3000) -> bool:
        """Check if an element matching the selector is visible.

        Args:
            selector: CSS selector to check.
            timeout_ms: How long to wait for the element.

        Returns:
            True if a visible element was found.
        """
        assert self._page is not None
        try:
            locator = self._page.locator(selector).first
            await locator.wait_for(state="visible", timeout=timeout_ms)
            return True
        except Exception:
            logger.debug("Element not visible for selector: %s", selector, exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Option / quick-reply handling
    # ------------------------------------------------------------------

    async def _detect_option_buttons(self) -> list[tuple[str, str]]:
        """Detect visible quick-reply / option buttons on the page.

        Returns:
            List of ``(selector, text)`` tuples for each visible option found.
            The selector identifies which pattern matched; the text is the
            button's visible label.
        """
        assert self._page is not None

        # Use explicit selector if configured
        selectors = (
            [self._browser_config.option_selector]
            if self._browser_config.option_selector
            else _OPTION_BUTTON_SELECTORS
        )

        found: list[tuple[str, str]] = []

        for selector in selectors:
            try:
                locator = self._page.locator(selector)
                count = await locator.count()
                for i in range(min(count, 20)):  # Cap at 20 options
                    el = locator.nth(i)
                    try:
                        if await el.is_visible(timeout=300):
                            text = (await el.inner_text()).strip()
                            if text and len(text) < 200:
                                found.append((selector, text))
                    except Exception:
                        logger.debug(
                            "Failed to read option button at index %d for selector: %s",
                            i,
                            selector,
                            exc_info=True,
                        )
                        continue
            except Exception:
                logger.debug(
                    "Failed to detect option buttons for selector: %s", selector, exc_info=True
                )
                continue

        # Deduplicate by text
        seen: set[str] = set()
        deduped: list[tuple[str, str]] = []
        for sel, text in found:
            if text.lower() not in seen:
                seen.add(text.lower())
                deduped.append((sel, text))

        return deduped

    async def _handle_initial_options(self) -> None:
        """Navigate through initial option menus to reach free-text mode.

        Many chatbots present quick-reply buttons as the first interaction.
        This method tries to get past those menus so that subsequent
        ``invoke()`` calls can reach the LLM reasoning layer.

        The strategy is controlled by ``browser_config.initial_options``:

        - ``auto`` — Try to find a "free text" / "other" option first,
          then click the first available option, up to ``max_option_depth``
          levels.
        - ``click_through`` — Click the first option at each level.
        - ``type_through`` — Do nothing; trust that typing will work.
        - ``skip`` — Do nothing.
        """
        assert self._page is not None

        strategy = self._browser_config.initial_options
        if strategy in ("skip", "type_through"):
            logger.debug("Option handling strategy=%s, skipping", strategy)
            return

        max_depth = self._browser_config.max_option_depth

        for depth in range(max_depth):
            # Wait for DOM to settle before detecting options.
            # First iteration waits longer (chatbot needs time to render
            # initial options after the launcher click).
            wait_ms = 3000 if depth == 0 else 2000
            await self._page.wait_for_timeout(wait_ms)

            options = await self._detect_option_buttons()
            if not options:
                logger.debug("No option buttons detected at depth %d", depth)
                return

            option_texts = [text for _, text in options]
            logger.info(
                "Detected %d option buttons at depth %d: %s",
                len(options),
                depth,
                option_texts[:5],
            )

            # Strategy: try user-configured preferred options first,
            # then built-in free-text patterns
            clicked = False

            # User-specified prefer_options always get first priority
            if self._browser_config.prefer_options:
                clicked = await self._click_preferred_option(options)

            if not clicked and strategy == "auto":
                clicked = await self._click_freetext_option(options)

            if not clicked:
                # Click the best available option
                clicked = await self._click_best_option(options)

            if not clicked:
                logger.warning("Could not click any option at depth %d, stopping", depth)
                return

            # Wait for response after clicking option
            await self._page.wait_for_timeout(2000)

        logger.info(
            "Navigated %d option levels (max_option_depth=%d)",
            max_depth,
            max_depth,
        )

    async def _click_preferred_option(self, options: list[tuple[str, str]]) -> bool:
        """Try to click an option matching user-configured ``prefer_options``.

        Matches case-insensitively as a substring against option button text.
        Patterns are tried in the order they appear in ``prefer_options``.

        Args:
            options: List of ``(selector, text)`` pairs.

        Returns:
            True if a preferred option was found and clicked.
        """
        assert self._page is not None

        for pattern in self._browser_config.prefer_options:
            pattern_lower = pattern.lower().strip()
            for _sel, text in options:
                if pattern_lower in text.lower().strip():
                    logger.info("Clicking preferred option %r (matched %r)", text, pattern)
                    return await self._click_option_by_text(text)

        return False

    async def _click_freetext_option(self, options: list[tuple[str, str]]) -> bool:
        """Try to click an option that leads to free-text mode.

        Looks for options matching patterns like "Something else",
        "Other", "Iets anders", etc.

        Args:
            options: List of ``(selector, text)`` pairs.

        Returns:
            True if a free-text option was found and clicked.
        """
        assert self._page is not None

        for _sel, text in options:
            text_lower = text.lower().strip()
            for pattern in _FREETEXT_OPTION_PATTERNS:
                if pattern in text_lower:
                    return await self._click_option_by_text(text)

        return False

    async def _click_best_option(self, options: list[tuple[str, str]]) -> bool:
        """Click the best available option button.

        Avoids "more" / "show more" style options that just expand the
        menu. Prefers the first substantive option.

        Args:
            options: List of ``(selector, text)`` pairs.

        Returns:
            True if an option was clicked.
        """
        assert self._page is not None

        # Partition into normal options and menu-deepening options
        normal: list[str] = []
        deepening: list[str] = []

        for _sel, text in options:
            text_lower = text.lower().strip()
            is_deepening = any(p in text_lower for p in _MENU_DEEPENING_PATTERNS)
            if is_deepening:
                deepening.append(text)
            else:
                normal.append(text)

        # Prefer normal options, fall back to deepening
        candidates = normal or deepening
        if not candidates:
            return False

        return await self._click_option_by_text(candidates[0])

    async def _click_option_by_text(self, text: str) -> bool:
        """Click a visible element that contains the given text.

        Uses Playwright's text matching to find the element.

        Args:
            text: The visible text of the option to click.

        Returns:
            True if the element was found and clicked.
        """
        assert self._page is not None

        # Try multiple strategies to click the option
        strategies = [
            f"button:has-text('{text}')",
            f"a:has-text('{text}')",
            f"[role='button']:has-text('{text}')",
            f"[role='option']:has-text('{text}')",
            f":has-text('{text}'):not(div:has(div:has-text('{text}')))",
        ]

        for selector in strategies:
            try:
                locator = self._page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    await locator.click(timeout=3000)
                    logger.info("Clicked option: '%s' via %s", text, selector)
                    return True
            except Exception:
                logger.debug("Failed to click option '%s' via %s", text, selector, exc_info=True)
                continue

        return False

    # ------------------------------------------------------------------
    # Network interception
    # ------------------------------------------------------------------

    async def _on_response(self, response: Response) -> None:
        """Callback for intercepted network responses."""
        if not self._detected_api_pattern:
            return

        # Check URL matches pattern
        url = response.url
        pattern = self._detected_api_pattern
        if not self._url_matches_pattern(url, pattern):
            return

        # Only capture successful POST responses with JSON
        if response.request.method != "POST":
            return
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type:
            return
        if response.status < 200 or response.status >= 300:
            return

        try:
            body = await response.json()
            self._intercepted_responses.append(body)
            logger.debug("Intercepted API response from %s", url)
        except Exception:
            logger.debug("Failed to parse JSON from intercepted response: %s", url)

    @staticmethod
    def _url_matches_pattern(url: str, pattern: str) -> bool:
        """Check if a URL matches a glob-style pattern.

        Supports ``**`` as wildcard for any path segments.
        """
        # Convert glob pattern to regex
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return bool(re.search(regex, url))

    # ------------------------------------------------------------------
    # WebSocket interception
    # ------------------------------------------------------------------

    def _on_websocket(self, ws: Any) -> None:
        """Callback when a WebSocket connection is established.

        Registers frame handlers for incoming and outgoing data.
        Filters by ``websocket_url_pattern`` if configured.
        """
        url: str = ws.url
        logger.debug("WebSocket connection opened: %s", url)

        # Filter by URL pattern if configured
        pattern = self._detected_ws_pattern or self._browser_config.websocket_url_pattern
        if pattern and not self._url_matches_pattern(url, pattern):
            logger.debug("WebSocket URL does not match pattern %s, ignoring", pattern)
            return

        self._ws_capture_active = True
        logger.info("Capturing WebSocket frames from: %s", url)

        ws.on("framereceived", lambda payload: self._on_ws_frame_received(payload))
        ws.on("framesent", lambda payload: self._on_ws_frame_sent(payload))
        ws.on("close", lambda: self._on_ws_close(url))

    def _on_ws_frame_received(self, payload: Any) -> None:
        """Handle an incoming WebSocket frame (bot → client).

        Parses Socket.IO frames to extract bot response content and
        appends to ``_intercepted_responses`` for the existing polling loop.
        """
        raw = payload.payload if hasattr(payload, "payload") else str(payload)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        # Try Socket.IO parsing first
        event_name, event_payload = parse_socketio_frame(raw)

        if event_name is not None and event_payload is not None:
            logger.debug("WebSocket Socket.IO event: %s", event_name)

            # Filter by event name
            target_event = (
                self._detected_ws_event or self._browser_config.websocket_event_name or None
            )
            if target_event:
                if event_name != target_event:
                    return
            elif event_name not in _WS_OUTPUT_EVENTS:
                # Auto-filter: only capture output-like events
                return

            # Extract content using configured or common paths
            ws_json_path = self._browser_config.websocket_message_path
            content = _extract_by_path(event_payload, ws_json_path) if ws_json_path else None
            if not isinstance(content, str) or not content:
                content = None

            if content is None:
                for path in _COMMON_WS_RESPONSE_PATHS:
                    result = _extract_by_path(event_payload, path)
                    if isinstance(result, str) and len(result.strip()) > 0:
                        content = result
                        break

            if content and isinstance(content, str) and len(content.strip()) > 0:
                # Build a response dict compatible with _extract_from_network()
                response_body: dict[str, Any] = {
                    "_ws_event": event_name,
                    "_ws_content": content,
                    "_ws_payload": event_payload,
                    "text": content,
                }
                self._intercepted_responses.append(response_body)
                logger.debug(
                    "WebSocket captured bot response: event=%s, content=%s...",
                    event_name,
                    content[:80],
                )

            # Store raw frame for detailed logging
            self._intercepted_ws_frames.append(
                {
                    "direction": "received",
                    "event": event_name,
                    "payload": event_payload,
                }
            )
            return

        # Fallback: try plain JSON (non-Socket.IO WebSocket)
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                ws_json_path = self._browser_config.websocket_message_path
                content = try_extract_content(data, ws_json_path)
                if content and isinstance(content, str) and len(content.strip()) > 0:
                    data["_ws_event"] = "raw"
                    data["_ws_content"] = content
                    self._intercepted_responses.append(data)
                    logger.debug("WebSocket captured plain JSON response: %s...", content[:80])
        except (json.JSONDecodeError, ValueError):
            pass

    def _on_ws_frame_sent(self, payload: Any) -> None:
        """Handle an outgoing WebSocket frame (client → bot).

        Captures the text of the outgoing message so the scan report
        can record what was actually sent (``prompt_used``).
        """
        raw = payload.payload if hasattr(payload, "payload") else str(payload)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        event_name, event_payload = parse_socketio_frame(raw)
        if event_name and event_payload:
            text = (
                event_payload.get("text")
                or event_payload.get("message")
                or (event_payload.get("data", {}) or {}).get("text", "")
            )
            if text:
                self._last_ws_sent_text = str(text)
                logger.debug("WebSocket captured outgoing message: %s...", str(text)[:80])

            self._intercepted_ws_frames.append(
                {
                    "direction": "sent",
                    "event": event_name,
                    "payload": event_payload,
                }
            )

    def _on_ws_close(self, url: str) -> None:
        """Handle WebSocket connection close."""
        logger.debug("WebSocket connection closed: %s", url)

    # ------------------------------------------------------------------
    # API auto-detection
    # ------------------------------------------------------------------

    async def _auto_detect_api_endpoint(self) -> None:
        """Send a probe and observe which POST requests fire.

        Heuristic: the API endpoint is the POST whose JSON body
        contains a field that looks like chat content.
        """
        assert self._page is not None

        candidates: list[tuple[str, dict[str, Any]]] = []

        async def capture(response: Response) -> None:
            if response.request.method != "POST":
                return
            content_type = response.headers.get("content-type", "")
            if "json" not in content_type:
                return
            try:
                body = await response.json()
                candidates.append((response.url, body))
            except Exception:
                logger.debug(
                    "Failed to parse JSON from captured response: %s", response.url, exc_info=True
                )

        self._page.on("response", capture)

        try:
            # Send a probe message through the UI
            await self._type_and_submit("Hello")
            # Wait for responses (half the configured timeout)
            wait_ms = int(self._browser_config.response_timeout * 500)
            await self._page.wait_for_timeout(wait_ms)
        except Exception:
            logger.debug("Auto-detect probe failed, falling back to DOM")
        finally:
            self._page.remove_listener("response", capture)

        # Score HTTP candidates
        for url, body in candidates:
            content = try_extract_content(body)
            if content and len(content) > 5:
                parsed = urlparse(url)
                self._detected_api_pattern = f"**{parsed.path}"
                logger.info("Auto-detected API endpoint: %s -> %s", url, self._detected_api_pattern)
                break
        else:
            # No HTTP API detected — check if WebSocket captured anything
            if self._intercepted_responses and self._ws_capture_active:
                logger.info(
                    "No HTTP API detected, but WebSocket captured %d responses. "
                    "Using WebSocket capture mode.",
                    len(self._intercepted_responses),
                )
                # Auto-detect the event name from captured frames
                for frame in self._intercepted_ws_frames:
                    if frame.get("direction") == "received" and frame.get("event"):
                        self._detected_ws_event = frame["event"]
                        logger.info("Auto-detected WebSocket event: %s", self._detected_ws_event)
                        break
            else:
                logger.warning("No API endpoint detected, falling back to DOM extraction")
                self._use_dom_fallback = True

        # Reload the page to start with a clean chat state.
        # The probe "Hello" message pollutes the conversation — without a
        # reload the chatbot would see *two* messages (the probe + the first
        # real invoke), which is the "double-message" bug.
        await self._reset_chat_after_probe()

    async def _reset_chat_after_probe(self) -> None:
        """Reload the page and re-run essential UI steps after the auto-detect probe.

        The auto-detect probe sends a "Hello" message which pollutes the
        conversation.  Without a reset the chatbot would see two messages
        in the first turn (the probe + the actual invoke) — the
        "double-message" bug.

        After reload we re-run cookie dismissal and launcher clicking (if
        the discovery phase clicked one) so the chat input is ready.
        Option handling is **not** re-run because
        ``_handle_initial_options()`` already populated the discovery
        state and will be re-triggered by the first ``invoke()`` if
        needed.
        """
        assert self._page is not None

        nav_timeout = self._browser_config.navigation_timeout * 1000
        await self._page.goto(self._config.url, timeout=nav_timeout)
        settle_ms = int(self._browser_config.settle_delay * 1000)
        await self._page.wait_for_timeout(settle_ms)

        # Re-dismiss cookie banners that may reappear on a fresh load
        await self._dismiss_cookie_banner()

        # Re-click the launcher if discovery found one earlier
        if not await self._is_element_visible(self._effective_input_selector, timeout_ms=2000):
            await self._find_and_click_launcher()
            await self._page.wait_for_timeout(1500)

        # Clear stale probe data so it doesn't leak into the first invoke
        self._intercepted_responses.clear()
        self._intercepted_ws_frames.clear()
        self._last_ws_sent_text = None

        logger.debug("Reset chat state after auto-detect probe")

    # ------------------------------------------------------------------
    # BaseAgentAdapter implementation
    # ------------------------------------------------------------------

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message through the chat UI and capture the response.

        Primary: intercept the underlying API call.
        Fallback: extract text from the DOM.

        If the chatbot responds with option buttons instead of a text
        response, the options are detected and included in the response
        metadata.

        Args:
            message: The message to send to the agent.

        Returns:
            Standardized agent response.
        """
        await self._ensure_initialized()
        assert self._page is not None

        # Clear previous interceptions
        self._intercepted_responses.clear()
        self._last_ws_sent_text = None

        # Snapshot DOM response count for diffing
        response_elements = await self._page.query_selector_all(self._effective_response_selector)
        self._last_response_count = len(response_elements)

        # Type and submit the message
        await self._type_and_submit(message)

        # Wait for response
        if self._use_dom_fallback:
            response = await self._extract_from_dom()
        else:
            response = await self._wait_for_network_response()

        # Detect option buttons that appeared with the response
        options = await self._detect_option_buttons()
        if options:
            option_texts = [text for _, text in options]
            response.metadata["option_buttons"] = option_texts
            logger.debug(
                "Response included %d option buttons: %s",
                len(options),
                option_texts[:5],
            )

        # Track conversation
        self._conversation.append({"role": "user", "content": message})
        self._conversation.append({"role": "assistant", "content": response.content})

        return response

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover agent capabilities via probe messages.

        Inspects intercepted API responses for tool schemas and
        sends probe messages to identify tool mentions.

        Returns:
            List of discovered capabilities.
        """
        await self._ensure_initialized()

        capabilities: dict[str, AgentCapability] = {}

        # Phase 1: Inspect any intercepted API responses for tool schemas
        for intercepted in self._intercepted_responses:
            for key in ("tools", "functions"):
                for tool_def in intercepted.get(key, []):
                    if isinstance(tool_def, dict):
                        name = tool_def.get("name", "")
                        fn = tool_def.get("function", {})
                        if not name and isinstance(fn, dict):
                            name = fn.get("name", "")
                        if name:
                            cap_id = f"api_{name}"
                            capabilities[cap_id] = AgentCapability(
                                id=cap_id,
                                name=name,
                                type=CapabilityType.TOOL,
                                description=tool_def.get("description", fn.get("description", "")),
                                parameters=tool_def.get("parameters", fn.get("parameters", {})),
                                dangerous=_is_dangerous_tool(name),
                            )

        # Phase 2: Probe-based discovery
        for probe in _DISCOVERY_PROBES:
            try:
                response = await self.invoke(probe)
                # Parse tool mentions from text
                for match in _TOOL_MENTION_RE.finditer(response.content):
                    name = match.group(1) or match.group(2)
                    if name:
                        cap_id = f"probe_{name}"
                        if cap_id not in capabilities:
                            capabilities[cap_id] = AgentCapability(
                                id=cap_id,
                                name=name,
                                type=CapabilityType.TOOL,
                                description=f"Discovered via probe: {probe[:50]}",
                                dangerous=_is_dangerous_tool(name),
                            )
            except Exception:
                logger.debug("Discovery probe failed: %s", probe[:50])
                continue

        return list(capabilities.values())

    def get_state(self) -> AgentState:
        """Return current adapter state snapshot."""
        return AgentState(
            session_id=self._session_id or "uninitialized",
            conversation_history=list(self._conversation),
            memory={
                "api_pattern": self._detected_api_pattern,
                "dom_fallback": self._use_dom_fallback,
                "tool_observations": list(self._tool_observations),
                "discovered_input_selector": self._discovered_input_selector,
                "discovered_submit_selector": self._discovered_submit_selector,
                "discovered_response_selector": self._discovered_response_selector,
                "ws_capture_active": self._ws_capture_active,
                "ws_pattern": self._detected_ws_pattern,
                "ws_event": self._detected_ws_event,
                "ws_frame_count": len(self._intercepted_ws_frames),
            },
        )

    def reset_state(self) -> None:
        """Clear conversation history and interception state."""
        self._conversation.clear()
        self._tool_observations.clear()
        self._intercepted_responses.clear()
        self._intercepted_ws_frames.clear()
        self._last_ws_sent_text = None
        self._last_response_count = 0

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call for analysis."""
        self._tool_observations.append(
            {
                "tool": tool_name,
                "inputs": inputs,
                "outputs": outputs,
                "timestamp": time.time(),
            }
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Shut down Playwright resources."""
        if self._page:
            await self._page.close()
            self._page = None
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _type_and_submit(self, message: str) -> None:
        """Type a message into the chat input and submit it.

        Uses discovered selectors (from auto-discovery) when available,
        falling back to the configured selectors.
        """
        assert self._page is not None

        # Prefer discovered selectors over defaults (but respect explicit config)
        input_sel = self._effective_input_selector
        submit_sel = self._effective_submit_selector

        # Find and focus the input
        input_el = await self._page.wait_for_selector(
            input_sel,
            timeout=self._browser_config.navigation_timeout * 1000,
        )
        if input_el is None:
            msg = f"Chat input not found with selector: {input_sel}"
            raise RuntimeError(msg)

        await input_el.click()
        # Clear existing text
        await input_el.fill("")
        await input_el.fill(message)

        # Submit
        if submit_sel:
            submit_btn = await self._page.wait_for_selector(
                submit_sel,
                timeout=5000,
            )
            if submit_btn:
                await submit_btn.click()
        else:
            await input_el.press("Enter")

    @property
    def _effective_input_selector(self) -> str:
        """Return the best input selector: explicit config > discovered > default."""
        if self._browser_config.input_selector != _DEFAULT_INPUT_SELECTOR:
            # User explicitly configured a selector — respect it
            return self._browser_config.input_selector
        return self._discovered_input_selector or self._browser_config.input_selector

    @property
    def _effective_submit_selector(self) -> str | None:
        """Return the best submit selector: explicit config > discovered > default."""
        if self._browser_config.submit_selector != _DEFAULT_SUBMIT_SELECTOR:
            return self._browser_config.submit_selector
        return self._discovered_submit_selector or self._browser_config.submit_selector

    @property
    def _effective_response_selector(self) -> str:
        """Return the best response selector: explicit config > discovered > default."""
        if self._browser_config.response_selector != _DEFAULT_RESPONSE_SELECTOR:
            return self._browser_config.response_selector
        return self._discovered_response_selector or self._browser_config.response_selector

    async def _wait_for_network_response(self) -> AgentResponse:
        """Wait for an intercepted API response and extract content."""
        assert self._page is not None

        timeout_ms = self._browser_config.response_timeout * 1000
        poll_interval_ms = 200
        elapsed = 0.0

        while elapsed < timeout_ms:
            if self._intercepted_responses:
                body = self._intercepted_responses[-1]
                return self._extract_from_network(body)
            await self._page.wait_for_timeout(poll_interval_ms)
            elapsed += poll_interval_ms

        # Network interception timed out — fall back to DOM
        logger.warning("Network interception timed out, falling back to DOM extraction")
        return await self._extract_from_dom()

    def _extract_from_network(self, body: dict[str, Any]) -> AgentResponse:
        """Extract an AgentResponse from an intercepted JSON body.

        Handles both HTTP-intercepted responses and WebSocket frames.
        WebSocket frames are identified by the ``_ws_content`` sentinel key.
        """
        is_ws = "_ws_content" in body
        extraction_mode = "websocket" if is_ws else "network"

        if is_ws:
            content = body.get("_ws_content", "")
            tool_calls: list[dict[str, Any]] = []
        else:
            content = try_extract_content(body, self._browser_config.response_json_path) or ""
            tool_calls = extract_tool_calls(body)

        # Estimate tokens from content
        word_count = len(content.split())
        est_completion = int(word_count / 0.75)

        # Try to get real token counts from response (HTTP only)
        usage = body.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0) if isinstance(usage, dict) else 0
        completion_tokens = (
            usage.get("completion_tokens", est_completion)
            if isinstance(usage, dict)
            else est_completion
        )
        total_tokens = (
            usage.get("total_tokens", prompt_tokens + completion_tokens)
            if isinstance(usage, dict)
            else prompt_tokens + completion_tokens
        )

        metadata: dict[str, Any] = {
            "protocol": "browser",
            "extraction_mode": extraction_mode,
        }
        if is_ws:
            metadata["ws_event"] = body.get("_ws_event", "")
            if self._last_ws_sent_text:
                metadata["prompt_used"] = self._last_ws_sent_text

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata=metadata,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )

    async def _extract_from_dom(self) -> AgentResponse:
        """Extract the latest assistant response from the DOM.

        Queries the response_selector, takes the last element, and
        extracts its text content.

        Returns:
            AgentResponse with content from the DOM.
        """
        assert self._page is not None

        # Wait for a new response element to appear
        resp_sel = self._effective_response_selector
        try:
            await self._page.wait_for_selector(
                resp_sel,
                timeout=self._browser_config.response_timeout * 1000,
            )
        except Exception:
            return AgentResponse(
                content="[No response detected in DOM]",
                tool_calls=[],
                metadata={"protocol": "browser", "extraction_mode": "dom", "error": "timeout"},
            )

        # Wait for DOM to settle (no more mutations)
        await self._wait_for_settle()

        elements = await self._page.query_selector_all(resp_sel)

        if not elements:
            return AgentResponse(
                content="[No response elements found]",
                tool_calls=[],
                metadata={"protocol": "browser", "extraction_mode": "dom", "error": "no_elements"},
            )

        # Get text from new response elements (after the last known count)
        new_elements = elements[self._last_response_count :]
        if new_elements:
            content = await new_elements[-1].inner_text()
        else:
            # Fall back to last element
            content = await elements[-1].inner_text()

        # Estimate tokens
        word_count = len(content.split())
        est_tokens = int(word_count / 0.75)

        return AgentResponse(
            content=content.strip(),
            tool_calls=[],  # DOM mode cannot observe tool calls
            metadata={
                "protocol": "browser",
                "extraction_mode": "dom",
                "response_count": len(elements),
            },
            prompt_tokens=0,
            completion_tokens=est_tokens,
            total_tokens=est_tokens,
        )

    async def _wait_for_settle(self) -> None:
        """Wait until DOM mutations have settled.

        Uses a MutationObserver that resolves when no changes occur
        for ``settle_delay`` seconds.
        """
        assert self._page is not None
        settle_ms = int(self._browser_config.settle_delay * 1000)

        try:
            await self._page.evaluate(f"""
                () => new Promise(resolve => {{
                    let timer = null;
                    const observer = new MutationObserver(() => {{
                        clearTimeout(timer);
                        timer = setTimeout(() => {{
                            observer.disconnect();
                            resolve();
                        }}, {settle_ms});
                    }});
                    observer.observe(document.body, {{
                        childList: true, subtree: true, characterData: true
                    }});
                    timer = setTimeout(() => {{
                        observer.disconnect();
                        resolve();
                    }}, {settle_ms});
                }})
            """)
        except Exception:
            # Fallback: simple wait
            await asyncio.sleep(self._browser_config.settle_delay)
