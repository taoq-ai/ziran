"""MCP (Model Context Protocol) handler.

Communicates with MCP-compliant tool servers using JSON-RPC 2.0
over HTTP. Discovers tools/resources and invokes them.

The server's era is decided once, before the first request, as the 2026-07-28 Streamable HTTP
binding says (spec 109): a ``server/discover`` probe with the modern per-request ``_meta``; a
``DiscoverResult`` or ``UnsupportedProtocolVersionError`` means a modern server, anything else a
legacy one, which gets the ``initialize`` handshake.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from functools import partial
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from ziran.domain.replies import NO_CHAT_REPLY
from ziran.infrastructure.adapters.protocols import (
    BaseProtocolHandler,
    ProtocolError,
    ProtocolResponse,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ziran.domain.entities.target import TargetConfig

logger = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"
MODERN_VERSION = "2026-07-28"
#: Revisions with the ``initialize`` handshake, newest first.
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
_HEADER_SINCE = "2025-06-18"  # the first revision with the MCP-Protocol-Version header
_UNSUPPORTED_VERSION = -32022
_MODERN_ERRORS = (-32020, -32021)  # HeaderMismatch, MissingRequiredClientCapability
_CLIENT_INFO = {"name": "ziran-scanner", "version": "0.1.0"}
# URL mode declared so a server shows the scan the elicitations it would show a user
_CLIENT_CAPABILITIES: dict[str, Any] = {"elicitation": {"form": {}, "url": {}}}
_NAME_FIELD = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
_MAX_ELICITATIONS = 20


def _header_value(value: str) -> str:
    """``value`` as an MCP header value: Base64 sentinel unless it is plain printable ASCII."""
    sentinel = value.startswith("=?base64?") and value.endswith("?=")
    if value.isascii() and value.isprintable() and value == value.strip() and not sentinel:
        return value
    return f"=?base64?{base64.b64encode(value.encode()).decode()}?="


def _json_object(load: Callable[[], Any]) -> dict[str, Any] | None:
    """``load()`` when it gives a JSON object; ``None`` for anything else, too-deep nesting too."""
    try:
        value = load()
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


class MCPProtocolHandler(BaseProtocolHandler):
    """Handler for Model Context Protocol servers.

    MCP uses JSON-RPC 2.0 with methods like ``tools/list``,
    ``tools/call``, and ``resources/list``.
    """

    def __init__(self, client: httpx.AsyncClient, config: TargetConfig) -> None:
        super().__init__(client, config)
        self._request_id = 0
        self._warned_no_chat = False
        self._lock = asyncio.Lock()
        self._era: str | None = None  # "modern" or "legacy" once negotiated
        self._version: str | None = None  # the MCP-Protocol-Version header value, when sent
        self._session_id: str | None = None
        self._reachable = False  # server/discover or initialize answered
        self._failure: str | None = None  # no protocol version in common

    async def send(self, message: str, **kwargs: Any) -> ProtocolResponse:
        """Send a message through ``completion/complete``, or ``tools/call`` for a tool.

        ``sampling/createMessage`` is a server-to-client request, so a client never sends
        it. When the server takes no chat prompt, the content is the no-chat placeholder,
        which the attack executors treat as a prompt error, never as a reply (spec 082).

        Args:
            message: The prompt to send.
            **kwargs: May include ``tool_name`` and ``arguments`` for
                direct tool invocation.

        Returns:
            Dict with ``content``, ``tool_calls``, and ``metadata``.
        """
        tool_name = kwargs.get("tool_name")
        if tool_name:
            return await self._call_tool(tool_name, kwargs.get("arguments", {}))

        method = "completion/complete"
        try:
            result, asked = await self._follow(
                method,
                {"messages": [{"role": "user", "content": {"type": "text", "text": message}}]},
            )
        except ProtocolError as exc:
            if not self._warned_no_chat:
                self._warned_no_chat = True
                # host, method and error class only: the URL and server text are untrusted
                logger.warning(
                    "MCP server %s took no chat prompt (%s failed: %s, HTTP %s); its "
                    "prompts count as errors, not replies",
                    httpx.URL(self._config.normalized_url).host,
                    method,
                    type(exc).__name__,
                    exc.status_code,
                )
            return {
                "content": NO_CHAT_REPLY,
                "tool_calls": [],
                "metadata": {"protocol": "mcp"},
            }
        return {
            "content": self._extract_content(result) + self._elicitation_text(asked),
            "tool_calls": [],
            "metadata": self._metadata(method, asked),
        }

    async def discover(self) -> list[dict[str, Any]]:
        """Discover MCP tools and resources.

        Returns:
            Combined list of tool and resource capability descriptors.
        """
        capabilities: list[dict[str, Any]] = []

        # Discover tools
        try:
            result = await self._jsonrpc_call("tools/list", {})
            for tool in result.get("tools", []):
                capabilities.append(
                    {
                        "id": tool.get("name", "unknown"),
                        "name": tool.get("name", "unknown"),
                        "type": "tool",
                        "description": tool.get("description", ""),
                        "parameters": tool.get("inputSchema", {}),
                    }
                )
        except ProtocolError:
            logger.debug("MCP tools/list not available")

        # Discover resources
        try:
            result = await self._jsonrpc_call("resources/list", {})
            for resource in result.get("resources", []):
                capabilities.append(
                    {
                        "id": resource.get("uri", resource.get("name", "unknown")),
                        "name": resource.get("name", "unknown"),
                        "type": "data_access",
                        "description": resource.get("description", ""),
                        "mimeType": resource.get("mimeType", ""),
                    }
                )
        except ProtocolError:
            logger.debug("MCP resources/list not available")

        # Discover prompts
        try:
            result = await self._jsonrpc_call("prompts/list", {})
            for prompt in result.get("prompts", []):
                capabilities.append(
                    {
                        "id": prompt.get("name", "unknown"),
                        "name": prompt.get("name", "unknown"),
                        "type": "skill",
                        "description": prompt.get("description", ""),
                    }
                )
        except ProtocolError:
            logger.debug("MCP prompts/list not available")

        return capabilities

    async def health_check(self) -> bool:
        """True when the server answered ``server/discover`` or ``initialize``."""
        try:
            await self._negotiate()
        except ProtocolError:
            return False
        return self._reachable

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ProtocolResponse:
        """Invoke a specific MCP tool.

        Args:
            tool_name: The tool to call.
            arguments: Tool arguments.

        Returns:
            Response dict.
        """
        result, asked = await self._follow(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
        content = self._extract_content(result) + self._elicitation_text(asked)
        return {
            "content": content,
            "tool_calls": [{"name": tool_name, "arguments": arguments}],
            "metadata": self._metadata("tools/call", asked),
        }

    async def _negotiate(self) -> None:
        """Decide the server's era once, from a ``server/discover`` probe (spec 109)."""
        async with self._lock:
            if self._era is None:
                await self._probe()
        if self._failure is not None:
            raise ProtocolError(self._failure, status_code=400)

    async def _probe(self) -> None:
        _, message = await self._exchange("server/discover", self._modern({}), MODERN_VERSION)
        result = message.get("result") if message else None
        error = message.get("error") if message else None
        offered: list[str] | None = None
        if isinstance(result, dict) and isinstance(result.get("supportedVersions"), list):
            offered = [str(v) for v in result["supportedVersions"]]
        elif isinstance(error, dict) and error.get("code") == _UNSUPPORTED_VERSION:
            data = error.get("data")
            supported = data.get("supported") if isinstance(data, dict) else None
            offered = [str(v) for v in supported] if isinstance(supported, list) else []
        elif isinstance(error, dict) and error.get("code") in _MODERN_ERRORS:
            self._era = "modern"
            self._failure = f"MCP server rejected the modern request (code {error['code']})"
            return
        if offered is not None and MODERN_VERSION in offered:
            self._era, self._version, self._reachable = "modern", MODERN_VERSION, True
            return
        self._era = "legacy"
        legacy = [v for v in LEGACY_VERSIONS if offered is None or v in offered]
        if not legacy:
            # the versions are the server's text: bounded and repr'd
            shown = [v[:32] for v in offered or []][:8]
            self._failure = f"MCP server supports none of ziran's protocol versions: {shown!r}"
            logger.warning("%s", self._failure)
            return
        await self._initialize(legacy[0])

    async def _initialize(self, requested: str) -> None:
        params = {"protocolVersion": requested, "capabilities": {}, "clientInfo": _CLIENT_INFO}
        response, message = await self._exchange("initialize", params, None)
        result = message.get("result") if message and response.status_code < 400 else None
        if not isinstance(result, dict):
            return  # no handshake: today's bare requests still reach a minimal server
        self._reachable = True
        agreed = result.get("protocolVersion")
        if agreed in LEGACY_VERSIONS and str(agreed) >= _HEADER_SINCE:
            self._version = str(agreed)
        session = response.headers.get("mcp-session-id")
        if isinstance(session, str) and session.isascii() and session.isprintable():
            self._session_id = session
        notice = {"jsonrpc": _JSONRPC_VERSION, "method": "notifications/initialized"}
        try:
            await self._client.post(
                self._config.normalized_url, json=notice, headers=self._headers(notice)
            )
        except httpx.HTTPError:
            logger.debug("MCP notifications/initialized not delivered")

    def _modern(self, params: dict[str, Any]) -> dict[str, Any]:
        meta = {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": _CLIENT_CAPABILITIES,
        }
        return {**params, "_meta": meta}

    def _headers(self, payload: dict[str, Any], version: str | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream"}
        version = version or self._version
        if version:
            headers["MCP-Protocol-Version"] = version
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        method = str(payload.get("method", ""))
        if "_meta" in payload.get("params", {}):  # the modern binding's request headers
            headers["Mcp-Method"] = _header_value(method)
            name = payload["params"].get(_NAME_FIELD.get(method, ""))
            if isinstance(name, str):
                headers["Mcp-Name"] = _header_value(name)
        return headers

    async def _exchange(
        self, method: str, params: dict[str, Any], version: str | None
    ) -> tuple[httpx.Response, dict[str, Any] | None]:
        """POST one request; the response and its JSON-RPC message (``None`` when unreadable).

        Raises:
            ProtocolError: On a transport failure.
        """
        self._request_id += 1
        rid = self._request_id
        payload = {"jsonrpc": _JSONRPC_VERSION, "id": rid, "method": method, "params": params}
        try:
            response = await self._client.post(
                self._config.normalized_url,
                json=payload,
                headers=self._headers(payload, version),
            )
        except httpx.HTTPError as exc:
            msg = f"MCP JSON-RPC call '{method}' failed: {exc}"
            raise ProtocolError(msg) from exc
        if "text/event-stream" not in str(response.headers.get("content-type", "")):
            return response, _json_object(response.json)
        # shortcut: one-line data fields only; multi-line SSE data is not joined
        for line in response.text.splitlines():
            data = line[5:] if line.startswith("data:") else ""
            event = _json_object(partial(json.loads, data)) if data else None
            if event is not None and event.get("id") == rid:
                return response, event
        return response, None

    async def _jsonrpc_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a JSON-RPC 2.0 call in the server's era.

        Args:
            method: The RPC method name.
            params: Method parameters.

        Returns:
            The ``result`` field from the JSON-RPC response.

        Raises:
            ProtocolError: On transport or JSON-RPC errors.
        """
        await self._negotiate()
        if self._era == "modern":
            params = self._modern(params)
        response, message = await self._exchange(method, params, None)
        if response.status_code >= 400:
            msg = f"MCP JSON-RPC call '{method}' failed with HTTP {response.status_code}"
            raise ProtocolError(
                msg, status_code=response.status_code, headers=dict(response.headers)
            )
        if message is None:
            msg = f"MCP JSON-RPC call '{method}' answered no JSON-RPC message (not JSON)"
            raise ProtocolError(msg)
        if "error" in message:
            err = message["error"] if isinstance(message["error"], dict) else {}
            msg = f"MCP JSON-RPC error {err.get('code')}: {err.get('message', 'unknown')}"
            raise ProtocolError(msg)
        result = message.get("result", {})
        return result if isinstance(result, dict) else {}

    async def _follow(
        self, method: str, params: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Call ``method``; an ``input_required`` result is recorded, declined and retried once.

        A scanner never opens a target's URL or fills its form, so every elicitation is
        declined. Returns the final result (empty while input is still required) and the
        elicitation records.
        """
        result = await self._jsonrpc_call(method, params)
        if result.get("resultType") != "input_required":
            return result, []
        asked = result.get("inputRequests")
        asked = asked if isinstance(asked, dict) else {}
        records = [
            self._elicitation(str(key), request)
            for key, request in list(asked.items())[:_MAX_ELICITATIONS]
            if isinstance(request, dict) and request.get("method") == "elicitation/create"
        ]
        state = result.get("requestState")
        if len(records) == len(asked) and (asked or isinstance(state, str)):
            retry = {**params, "inputResponses": {r["key"]: {"action": "decline"} for r in records}}
            if isinstance(state, str):
                retry["requestState"] = state
            final = await self._jsonrpc_call(method, retry)
            if final.get("resultType") != "input_required":
                return final, records
        return {}, records

    def _elicitation(self, key: str, request: dict[str, Any]) -> dict[str, Any]:
        """One elicitation request as a record; a URL off the server's host is flagged."""
        params = request.get("params")
        params = params if isinstance(params, dict) else {}
        mode, message, url = params.get("mode"), params.get("message"), params.get("url")
        url = url[:2048] if isinstance(url, str) else None
        url_host = _host(url) if url is not None else None
        foreign = url is not None and url_host != _host(self._config.normalized_url)
        if foreign:
            logger.warning(
                "MCP server %s asked the client to open a URL on host %r",
                _host(self._config.normalized_url),
                (url_host or "")[:100],
            )
        return {
            "key": key,
            "mode": mode[:20] if isinstance(mode, str) else "form",
            "message": message[:500] if isinstance(message, str) else "",
            "url": url,
            "url_host": url_host,
            "foreign_host": foreign,
        }

    def _elicitation_text(self, records: list[dict[str, Any]]) -> str:
        """The URL elicitations as reply lines, so the scan's recorded reply keeps them."""
        server = _host(self._config.normalized_url)
        lines = [
            f"\n[MCP elicitation] {r['message']} URL: {r['url']}"
            + (
                f" (host {r['url_host']!r} is not the server host {server!r})"
                if r["foreign_host"]
                else ""
            )
            for r in records
            if r["url"] is not None
        ]
        return "".join(lines)

    @staticmethod
    def _metadata(method: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        metadata: dict[str, Any] = {"method": method, "protocol": "mcp"}
        if records:
            metadata["mcp_input_required"] = records
        return metadata

    @staticmethod
    def _extract_content(result: dict[str, Any]) -> str:
        """Extract text content from an MCP response.

        Args:
            result: The JSON-RPC result payload.

        Returns:
            Extracted text content.
        """
        # Handle content array (MCP standard)
        content_items = result.get("content", [])
        if isinstance(content_items, list):
            texts = []
            for item in content_items:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
            if texts:
                return "\n".join(texts)

        # Handle completion object
        completion = result.get("completion", {})
        if isinstance(completion, dict) and "values" in completion:
            return ", ".join(str(v) for v in completion["values"])

        # Fallback: serialize the whole result
        if result:
            return json.dumps(result, indent=2)
        return ""
