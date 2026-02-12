"""MCP (Model Context Protocol) handler.

Communicates with MCP-compliant tool servers using JSON-RPC 2.0
over HTTP. Discovers tools/resources and invokes them.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

if TYPE_CHECKING:
    from ziran.domain.entities.target import TargetConfig

logger = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"


class MCPProtocolHandler(BaseProtocolHandler):
    """Handler for Model Context Protocol servers.

    MCP uses JSON-RPC 2.0 with methods like ``tools/list``,
    ``tools/call``, and ``resources/list``.
    """

    def __init__(self, client: httpx.AsyncClient, config: TargetConfig) -> None:
        super().__init__(client, config)
        self._request_id = 0

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a message by invoking the MCP server's chat/prompt method.

        Since MCP servers are primarily tool providers, this wraps the
        message in a ``completion/complete`` or falls back to a
        ``tools/call`` if a specific tool is targeted.

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

        # Try completion/complete first; fall back to sampling/createMessage
        for method in ("completion/complete", "sampling/createMessage"):
            try:
                result = await self._jsonrpc_call(
                    method,
                    {"messages": [{"role": "user", "content": {"type": "text", "text": message}}]},
                )
                content = self._extract_content(result)
                return {
                    "content": content,
                    "tool_calls": [],
                    "metadata": {"method": method, "protocol": "mcp"},
                }
            except ProtocolError:
                continue

        # If no completion method works, return an indicator message
        return {
            "content": "[MCP server does not support direct messaging — use tools/call]",
            "tool_calls": [],
            "metadata": {"protocol": "mcp"},
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
        """Check MCP server with an initialize handshake."""
        try:
            await self._jsonrpc_call(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "ziran-scanner", "version": "0.1.0"},
                },
            )
            return True
        except ProtocolError:
            return False

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a specific MCP tool.

        Args:
            tool_name: The tool to call.
            arguments: Tool arguments.

        Returns:
            Response dict.
        """
        result = await self._jsonrpc_call(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
        content = self._extract_content(result)
        return {
            "content": content,
            "tool_calls": [{"name": tool_name, "arguments": arguments}],
            "metadata": {"method": "tools/call", "protocol": "mcp"},
        }

    async def _jsonrpc_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a JSON-RPC 2.0 call.

        Args:
            method: The RPC method name.
            params: Method parameters.

        Returns:
            The ``result`` field from the JSON-RPC response.

        Raises:
            ProtocolError: On transport or JSON-RPC errors.
        """
        self._request_id += 1
        payload = {
            "jsonrpc": _JSONRPC_VERSION,
            "id": self._request_id,
            "method": method,
            "params": params,
        }

        try:
            response = await self._client.post(
                self._config.normalized_url,
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"MCP JSON-RPC call '{method}' failed with HTTP {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"MCP JSON-RPC call '{method}' failed: {exc}"
            raise ProtocolError(msg) from exc

        data = response.json()

        if "error" in data:
            err = data["error"]
            msg = f"MCP JSON-RPC error {err.get('code')}: {err.get('message', 'unknown')}"
            raise ProtocolError(msg)

        result: dict[str, Any] = data.get("result", {})
        return result

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
