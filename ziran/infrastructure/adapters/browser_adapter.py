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

        # Set up network interception
        if self._browser_config.api_url_pattern:
            self._detected_api_pattern = self._browser_config.api_url_pattern
        self._page.on("response", self._on_response)

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
                pass

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

        # Score candidates
        for url, body in candidates:
            content = try_extract_content(body)
            if content and len(content) > 5:
                parsed = urlparse(url)
                self._detected_api_pattern = f"**{parsed.path}"
                logger.info("Auto-detected API endpoint: %s -> %s", url, self._detected_api_pattern)
                return

        logger.warning("No API endpoint detected, falling back to DOM extraction")
        self._use_dom_fallback = True

    # ------------------------------------------------------------------
    # BaseAgentAdapter implementation
    # ------------------------------------------------------------------

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message through the chat UI and capture the response.

        Primary: intercept the underlying API call.
        Fallback: extract text from the DOM.

        Args:
            message: The message to send to the agent.

        Returns:
            Standardized agent response.
        """
        await self._ensure_initialized()
        assert self._page is not None

        # Clear previous interceptions
        self._intercepted_responses.clear()

        # Snapshot DOM response count for diffing
        response_elements = await self._page.query_selector_all(
            self._browser_config.response_selector
        )
        self._last_response_count = len(response_elements)

        # Type and submit the message
        await self._type_and_submit(message)

        # Wait for response
        if self._use_dom_fallback:
            response = await self._extract_from_dom()
        else:
            response = await self._wait_for_network_response()

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
            },
        )

    def reset_state(self) -> None:
        """Clear conversation history and interception state."""
        self._conversation.clear()
        self._tool_observations.clear()
        self._intercepted_responses.clear()
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
        """Type a message into the chat input and submit it."""
        assert self._page is not None

        # Find and focus the input
        input_el = await self._page.wait_for_selector(
            self._browser_config.input_selector,
            timeout=self._browser_config.navigation_timeout * 1000,
        )
        if input_el is None:
            msg = f"Chat input not found with selector: {self._browser_config.input_selector}"
            raise RuntimeError(msg)

        await input_el.click()
        # Clear existing text
        await input_el.fill("")
        await input_el.fill(message)

        # Submit
        if self._browser_config.submit_selector:
            submit_btn = await self._page.wait_for_selector(
                self._browser_config.submit_selector,
                timeout=5000,
            )
            if submit_btn:
                await submit_btn.click()
        else:
            await input_el.press("Enter")

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
        """Extract an AgentResponse from an intercepted JSON body."""
        content = try_extract_content(body, self._browser_config.response_json_path) or ""
        tool_calls = extract_tool_calls(body)

        # Estimate tokens from content
        word_count = len(content.split())
        est_completion = int(word_count / 0.75)

        # Try to get real token counts from response
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

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata={
                "protocol": "browser",
                "extraction_mode": "network",
            },
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
        try:
            await self._page.wait_for_selector(
                self._browser_config.response_selector,
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

        elements = await self._page.query_selector_all(self._browser_config.response_selector)

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
