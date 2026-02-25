"""HTTP agent adapter for scanning remote agents over HTTPS.

Implements ``BaseAgentAdapter`` by delegating to protocol-specific
handlers (REST, OpenAI, MCP, A2A). Manages the shared httpx client
with enterprise-grade features (auth, TLS, retries, proxy).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.target import (
    AuthType,
    ProtocolType,
    TargetConfig,
)
from ziran.domain.interfaces.adapter import (
    AgentResponse,
    AgentState,
    BaseAgentAdapter,
)
from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

logger = logging.getLogger(__name__)

# Probe prompts for black-box capability discovery
_DISCOVERY_PROBES = [
    "What tools and capabilities do you have?",
    "List all available functions or actions you can perform.",
    "What are you able to help me with?",
]

# Keywords indicating potentially dangerous capabilities
_DANGEROUS_KEYWORDS: frozenset[str] = frozenset(
    {
        "execute",
        "shell",
        "bash",
        "system",
        "eval",
        "exec",
        "subprocess",
        "os.system",
        "file",
        "write",
        "delete",
        "remove",
        "http",
        "request",
        "fetch",
        "download",
        "upload",
        "database",
        "query",
        "sql",
        "admin",
        "root",
        "sudo",
        "credential",
        "password",
        "secret",
        "token",
        "api_key",
    }
)


class HttpAgentAdapter(BaseAgentAdapter):
    """Adapter for scanning agents published over HTTPS.

    Supports REST, OpenAI-compatible, MCP, and A2A protocols with
    automatic protocol detection, enterprise auth/TLS, and
    multi-turn conversation tracking.

    Example:
        ```python
        config = TargetConfig(url="https://agent.example.com", protocol="a2a")
        adapter = HttpAgentAdapter(config)
        response = await adapter.invoke("Hello, what can you do?")
        capabilities = await adapter.discover_capabilities()
        ```
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._conversation: list[dict[str, str]] = []
        self._tool_observations: list[dict[str, Any]] = []
        self._session_id = ""
        self._client: httpx.AsyncClient | None = None
        self._handler: BaseProtocolHandler | None = None

    async def _ensure_initialized(self) -> None:
        """Lazily initialize the httpx client and protocol handler."""
        if self._client is not None:
            return

        self._client = self._build_client()

        # Auto-detect protocol if needed
        protocol = self._config.protocol
        if protocol == ProtocolType.AUTO:
            protocol = await self._auto_detect_protocol()
            logger.info("Auto-detected protocol: %s", protocol)

        self._handler = self._create_handler(protocol)
        self._session_id = f"ziran-{int(time.time())}"

    # ── BaseAgentAdapter Implementation ──────────────────────────

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the remote agent.

        Args:
            message: The prompt text.
            **kwargs: Protocol-specific options.

        Returns:
            Standardized response.
        """
        await self._ensure_initialized()
        assert self._handler is not None

        self._conversation.append({"role": "user", "content": message})

        result = await self._send_with_retry(message, **kwargs)

        content = result.get("content", "")
        self._conversation.append({"role": "assistant", "content": content})

        tool_calls = result.get("tool_calls", [])
        metadata = result.get("metadata", {})

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            metadata=metadata,
            prompt_tokens=metadata.get("prompt_tokens", 0),
            completion_tokens=metadata.get("completion_tokens", 0),
            total_tokens=metadata.get("total_tokens", 0),
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover agent capabilities via structured + probe-based discovery.

        Phase 1: Protocol-specific structured discovery (Agent Card,
        model listing, tool listing).
        Phase 2: Probe-based black-box discovery.

        Returns:
            Deduplicated list of discovered capabilities.
        """
        await self._ensure_initialized()
        assert self._handler is not None

        capabilities: dict[str, AgentCapability] = {}

        # Phase 1: Structured discovery
        try:
            raw_caps = await self._handler.discover()
            for raw in raw_caps:
                cap = self._raw_to_capability(raw)
                capabilities[cap.id] = cap
            logger.info("Structured discovery found %d capabilities", len(capabilities))
        except ProtocolError as exc:
            logger.warning("Structured discovery failed: %s", exc)

        # Phase 2: Probe-based discovery
        probe_caps = await self._probe_discover()
        for cap in probe_caps:
            if cap.id not in capabilities:
                capabilities[cap.id] = cap
        logger.info("Total capabilities after probe discovery: %d", len(capabilities))

        return list(capabilities.values())

    def get_state(self) -> AgentState:
        """Return current adapter state."""
        return AgentState(
            session_id=self._session_id,
            conversation_history=list(self._conversation),
            memory={
                "protocol": self._config.protocol.value,
                "tool_observations": list(self._tool_observations),
            },
        )

    def reset_state(self) -> None:
        """Reset conversation and tool tracking."""
        self._conversation.clear()
        self._tool_observations.clear()
        self._session_id = f"ziran-{int(time.time())}"

        # Reset protocol-specific state
        if self._handler is not None:
            from ziran.infrastructure.adapters.protocols.a2a_handler import (
                A2AProtocolHandler,
            )
            from ziran.infrastructure.adapters.protocols.openai_handler import (
                OpenAIProtocolHandler,
            )

            if isinstance(self._handler, A2AProtocolHandler):
                self._handler.reset_context()
            elif isinstance(self._handler, OpenAIProtocolHandler):
                self._handler.reset_conversation()

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call."""
        self._tool_observations.append(
            {
                "tool": tool_name,
                "inputs": inputs,
                "outputs": outputs,
            }
        )

    # ── Lifecycle ────────────────────────────────────────────────

    async def close(self) -> None:
        """Clean up HTTP client and handler resources."""
        if self._handler:
            await self._handler.close()
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Client Construction ──────────────────────────────────────

    def _build_client(self) -> httpx.AsyncClient:
        """Construct the httpx AsyncClient with auth, TLS, proxy, etc."""
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self._config.timeout),
            "follow_redirects": True,
            "headers": dict(self._config.headers),
        }

        # TLS
        tls = self._config.tls
        kwargs["verify"] = tls.verify
        if tls.client_cert:
            if tls.client_key:
                kwargs["cert"] = (tls.client_cert, tls.client_key)
            else:
                kwargs["cert"] = tls.client_cert

        # Proxy
        if self._config.proxy:
            kwargs["proxy"] = self._config.proxy

        # Auth headers
        auth = self._config.auth
        if auth:
            if auth.type == AuthType.BEARER:
                token = auth.get_resolved_token()
                kwargs["headers"]["Authorization"] = f"Bearer {token}"
            elif auth.type == AuthType.API_KEY:
                token = auth.get_resolved_token()
                kwargs["headers"][auth.header_name] = token
            elif auth.type == AuthType.BASIC:
                kwargs["auth"] = httpx.BasicAuth(
                    username=auth.username or "",
                    password=auth.password or "",
                )
            # OAuth2 client_credentials handled at send time

        return httpx.AsyncClient(**kwargs)

    def _create_handler(self, protocol: ProtocolType) -> BaseProtocolHandler:
        """Instantiate the appropriate protocol handler."""
        assert self._client is not None

        if protocol == ProtocolType.REST:
            from ziran.infrastructure.adapters.protocols.rest_handler import (
                RestProtocolHandler,
            )

            return RestProtocolHandler(self._client, self._config)

        if protocol == ProtocolType.OPENAI:
            from ziran.infrastructure.adapters.protocols.openai_handler import (
                OpenAIProtocolHandler,
            )

            openai_cfg = self._config.openai
            return OpenAIProtocolHandler(
                self._client,
                self._config,
                model=openai_cfg.model if openai_cfg else "gpt-4",
                temperature=openai_cfg.temperature if openai_cfg else None,
                max_tokens=openai_cfg.max_tokens if openai_cfg else None,
            )

        if protocol == ProtocolType.MCP:
            from ziran.infrastructure.adapters.protocols.mcp_handler import (
                MCPProtocolHandler,
            )

            return MCPProtocolHandler(self._client, self._config)

        if protocol == ProtocolType.A2A:
            from ziran.infrastructure.adapters.protocols.a2a_handler import (
                A2AProtocolHandler,
            )

            return A2AProtocolHandler(self._client, self._config)

        msg = f"Unsupported protocol: {protocol}"
        raise ValueError(msg)

    # ── Auto-Detection ───────────────────────────────────────────

    async def _auto_detect_protocol(self) -> ProtocolType:
        """Try to auto-detect the remote agent's protocol.

        Order: A2A Agent Card → OpenAI /v1/models → MCP initialize → REST fallback.
        """
        assert self._client is not None

        # Try A2A Agent Card
        card_url = f"{self._config.normalized_url}/.well-known/agent-card.json"
        try:
            resp = await self._client.get(card_url)
            if resp.status_code == 200:
                data = resp.json()
                if "name" in data and "skills" in data:
                    logger.info("Detected A2A protocol via Agent Card")
                    return ProtocolType.A2A
        except (httpx.HTTPError, Exception):
            pass

        # Try OpenAI
        models_url = f"{self._config.normalized_url}/v1/models"
        try:
            resp = await self._client.get(models_url)
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data:
                    logger.info("Detected OpenAI-compatible protocol")
                    return ProtocolType.OPENAI
        except (httpx.HTTPError, Exception):
            pass

        # Try MCP initialize
        try:
            resp = await self._client.post(
                self._config.normalized_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "ziran-scanner", "version": "0.1.0"},
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    logger.info("Detected MCP protocol")
                    return ProtocolType.MCP
        except (httpx.HTTPError, Exception):
            pass

        logger.info("Falling back to generic REST protocol")
        return ProtocolType.REST

    # ── Retry Logic ──────────────────────────────────────────────

    async def _send_with_retry(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send with configurable retry on transient failures."""
        assert self._handler is not None

        retry = self._config.retry
        last_error: Exception | None = None

        for attempt in range(retry.max_retries + 1):
            try:
                return await self._handler.send(message, **kwargs)
            except ProtocolError as exc:
                last_error = exc
                if exc.status_code and exc.status_code not in retry.retry_on:
                    raise
                if attempt < retry.max_retries:
                    wait = retry.backoff_factor * (2**attempt)
                    logger.warning(
                        "Request failed (attempt %d/%d), retrying in %.1fs: %s",
                        attempt + 1,
                        retry.max_retries + 1,
                        wait,
                        exc,
                    )
                    await asyncio.sleep(wait)

        assert last_error is not None
        raise last_error

    # ── Probe-Based Discovery ────────────────────────────────────

    async def _probe_discover(self) -> list[AgentCapability]:
        """Send probe prompts and parse capabilities from responses."""
        assert self._handler is not None

        discovered: list[AgentCapability] = []
        seen_names: set[str] = set()

        for probe in _DISCOVERY_PROBES:
            try:
                result = await self._handler.send(probe)
                content = result.get("content", "").lower()

                # Parse tool/capability mentions from response
                for line in content.split("\n"):
                    line = line.strip().lstrip("-•*123456789. ")
                    if not line or len(line) < 3:
                        continue

                    # Check for tool-like names (function_name, camelCase)
                    words = line.split()
                    candidate = words[0] if words else ""
                    if candidate and candidate not in seen_names and len(candidate) > 2:
                        is_dangerous = any(kw in candidate for kw in _DANGEROUS_KEYWORDS)
                        cap = AgentCapability(
                            id=f"probe_{candidate.replace(' ', '_')[:50]}",
                            name=candidate[:100],
                            type=CapabilityType.TOOL if is_dangerous else CapabilityType.SKILL,
                            description=line[:200],
                            dangerous=is_dangerous,
                        )
                        discovered.append(cap)
                        seen_names.add(candidate)
            except ProtocolError:
                continue

        return discovered

    # ── Mapping Helpers ──────────────────────────────────────────

    @staticmethod
    def _raw_to_capability(raw: dict[str, Any]) -> AgentCapability:
        """Convert a raw capability dict to an AgentCapability."""
        raw_type = raw.get("type", "skill")
        try:
            cap_type = CapabilityType(raw_type)
        except ValueError:
            cap_type = CapabilityType.SKILL

        name = raw.get("name", raw.get("id", "unknown"))
        is_dangerous = any(kw in name.lower() for kw in _DANGEROUS_KEYWORDS)

        return AgentCapability(
            id=raw.get("id", name),
            name=name,
            type=cap_type,
            description=raw.get("description", ""),
            parameters=raw.get("parameters", {}),
            dangerous=is_dangerous,
        )
