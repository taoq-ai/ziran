"""A2A (Agent-to-Agent) protocol handler.

Implements the A2A Protocol Specification (RC v1.0) client operations
needed for Ziran's security scanning. Supports both the HTTP+JSON
(REST) and JSON-RPC protocol bindings, Agent Card discovery,
multi-turn conversations via contextId/taskId, and SSE streaming.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx

from ziran.domain.entities.a2a import (
    A2AAgentCard,
    A2AMessage,
    A2APart,
    A2ASendMessageConfiguration,
    A2ASendMessageRequest,
    A2ASendMessageResponse,
    A2ATask,
)
from ziran.domain.entities.target import A2AConfig, TargetConfig
from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

logger = logging.getLogger(__name__)

_DEFAULT_A2A_VERSION = "1.0"
_WELL_KNOWN_AGENT_CARD = "/.well-known/agent-card.json"


class A2AProtocolHandler(BaseProtocolHandler):
    """Handler for A2A-compliant agents.

    Leverages the Agent Card for structured capability discovery,
    then uses ``SendMessage`` (HTTP+JSON or JSON-RPC binding) for
    prompt delivery with multi-turn support.
    """

    def __init__(self, client: httpx.AsyncClient, config: TargetConfig) -> None:
        super().__init__(client, config)
        self._a2a = config.a2a or A2AConfig()
        self._agent_card: A2AAgentCard | None = None
        self._context_id: str = str(uuid.uuid4())
        self._task_id: str | None = None
        self._jsonrpc_id = 0

    # ── Public API ───────────────────────────────────────────────

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a message to the A2A agent.

        Builds a ``SendMessageRequest``, dispatches it via the
        configured protocol binding, and extracts the response.

        Args:
            message: The prompt text.

        Returns:
            Dict with ``content``, ``tool_calls``, and ``metadata``.
        """
        msg = A2AMessage(
            message_id=str(uuid.uuid4()),
            context_id=self._context_id,
            task_id=self._task_id,
            role="ROLE_USER",
            parts=[A2APart(text=message)],
        )

        configuration = A2ASendMessageConfiguration(
            accepted_output_modes=["text/plain", "application/json"],
            blocking=self._a2a.blocking,
        )

        request = A2ASendMessageRequest(
            message=msg,
            configuration=configuration,
        )

        response = await self._send_message(request)

        # Update context for multi-turn
        if response.task:
            self._context_id = response.task.context_id or self._context_id
            self._task_id = response.task.id

        content = response.extract_text()
        metadata = self._build_response_metadata(response)

        return {
            "content": content,
            "tool_calls": self._extract_tool_calls(response),
            "metadata": metadata,
        }

    async def discover(self) -> list[dict[str, Any]]:
        """Discover capabilities from the Agent Card.

        Fetches the Agent Card (and optionally the extended card),
        then maps skills, security schemes, and capabilities into
        raw capability descriptors.

        Returns:
            List of capability dicts.
        """
        card = await self.fetch_agent_card()
        capabilities: list[dict[str, Any]] = []

        # Map skills
        for skill in card.skills:
            capabilities.append(
                {
                    "id": skill.id,
                    "name": skill.name,
                    "type": "skill",
                    "description": skill.description,
                    "tags": skill.tags,
                    "examples": skill.examples,
                    "input_modes": skill.input_modes,
                    "output_modes": skill.output_modes,
                }
            )

        # Map security schemes as capabilities (attack surface)
        schemes = card.parse_security_schemes()
        for name, scheme in schemes.items():
            capabilities.append(
                {
                    "id": f"security_scheme_{name}",
                    "name": f"Auth: {name} ({scheme.type})",
                    "type": "permission",
                    "description": scheme.description or f"Security scheme: {scheme.type}",
                    "auth_type": scheme.type,
                }
            )

        # Map agent-level capabilities
        if card.capabilities.streaming:
            capabilities.append(
                {
                    "id": "a2a_streaming",
                    "name": "SSE Streaming",
                    "type": "skill",
                    "description": "Agent supports Server-Sent Events streaming",
                }
            )
        if card.capabilities.push_notifications:
            capabilities.append(
                {
                    "id": "a2a_push_notifications",
                    "name": "Push Notifications (WebHooks)",
                    "type": "external_api",
                    "description": "Agent supports push notification webhooks",
                }
            )
        if card.capabilities.extended_agent_card:
            capabilities.append(
                {
                    "id": "a2a_extended_card",
                    "name": "Extended Agent Card",
                    "type": "permission",
                    "description": "Agent provides additional capabilities to authenticated clients",
                }
            )

        return capabilities

    async def health_check(self) -> bool:
        """Verify the agent by fetching its Agent Card."""
        try:
            await self.fetch_agent_card()
            return True
        except ProtocolError:
            return False

    # ── Agent Card ───────────────────────────────────────────────

    async def fetch_agent_card(self, force: bool = False) -> A2AAgentCard:
        """Fetch and parse the Agent Card.

        Args:
            force: Bypass cache and re-fetch.

        Returns:
            Parsed Agent Card.

        Raises:
            ProtocolError: If the card cannot be fetched or parsed.
        """
        if self._agent_card and not force:
            return self._agent_card

        card_url = self._resolve_agent_card_url()
        logger.info("Fetching A2A Agent Card from %s", card_url)

        try:
            response = await self._client.get(card_url)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"Failed to fetch Agent Card: HTTP {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"Failed to fetch Agent Card: {exc}"
            raise ProtocolError(msg) from exc

        try:
            data = response.json()
            self._agent_card = A2AAgentCard(**data)
        except Exception as exc:
            msg = f"Failed to parse Agent Card: {exc}"
            raise ProtocolError(msg) from exc

        logger.info(
            "Agent Card loaded: %s (v%s) with %d skills",
            self._agent_card.name,
            self._agent_card.version,
            len(self._agent_card.skills),
        )

        # Optionally fetch extended card
        if self._a2a.use_extended_card and self._agent_card.capabilities.extended_agent_card:
            await self._fetch_extended_card()

        return self._agent_card

    async def _fetch_extended_card(self) -> None:
        """Fetch the authenticated extended Agent Card."""
        url = f"{self._config.normalized_url}/extendedAgentCard"
        try:
            response = await self._client.get(url)
            response.raise_for_status()
            data = response.json()
            self._agent_card = A2AAgentCard(**data)
            logger.info("Extended Agent Card loaded with %d skills", len(self._agent_card.skills))
        except (httpx.HTTPError, Exception) as exc:
            logger.warning("Could not fetch extended Agent Card: %s", exc)

    # ── Message Sending ──────────────────────────────────────────

    async def _send_message(self, request: A2ASendMessageRequest) -> A2ASendMessageResponse:
        """Dispatch a SendMessage request via the configured binding.

        Args:
            request: The message request to send.

        Returns:
            Parsed response.
        """
        if self._a2a.protocol_binding == "JSONRPC":
            return await self._send_jsonrpc(request)
        return await self._send_http_json(request)

    async def _send_http_json(self, request: A2ASendMessageRequest) -> A2ASendMessageResponse:
        """Send via HTTP+JSON (REST) binding.

        ``POST /message:send`` with JSON body.
        """
        url = f"{self._config.normalized_url}/message:send"
        headers = {"A2A-Version": self._a2a.a2a_version}
        body = request.model_dump(by_alias=True, exclude_none=True)

        try:
            response = await self._client.post(url, json=body, headers=headers)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"A2A SendMessage failed: HTTP {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"A2A SendMessage failed: {exc}"
            raise ProtocolError(msg) from exc

        return self._parse_send_response(response.json())

    async def _send_jsonrpc(self, request: A2ASendMessageRequest) -> A2ASendMessageResponse:
        """Send via JSON-RPC 2.0 binding.

        ``POST /`` with JSON-RPC payload and method ``SendMessage``.
        """
        self._jsonrpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._jsonrpc_id,
            "method": "SendMessage",
            "params": request.model_dump(by_alias=True, exclude_none=True),
        }
        headers = {"A2A-Version": self._a2a.a2a_version}

        try:
            response = await self._client.post(
                self._config.normalized_url,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"A2A JSON-RPC SendMessage failed: HTTP {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"A2A JSON-RPC SendMessage failed: {exc}"
            raise ProtocolError(msg) from exc

        data = response.json()
        if "error" in data:
            err = data["error"]
            msg = f"A2A JSON-RPC error {err.get('code')}: {err.get('message', 'unknown')}"
            raise ProtocolError(msg)

        return self._parse_send_response(data.get("result", {}))

    # ── State Management ─────────────────────────────────────────

    def get_context_id(self) -> str:
        """Return the current A2A context ID."""
        return self._context_id

    def get_task_id(self) -> str | None:
        """Return the current A2A task ID, if any."""
        return self._task_id

    def reset_context(self) -> None:
        """Start a new conversation context."""
        self._context_id = str(uuid.uuid4())
        self._task_id = None

    @property
    def agent_card(self) -> A2AAgentCard | None:
        """Return the cached Agent Card, if fetched."""
        return self._agent_card

    # ── Helpers ──────────────────────────────────────────────────

    def _resolve_agent_card_url(self) -> str:
        """Build the Agent Card URL."""
        if self._a2a.agent_card_url:
            return self._a2a.agent_card_url
        return f"{self._config.normalized_url}{_WELL_KNOWN_AGENT_CARD}"

    @staticmethod
    def _parse_send_response(data: dict[str, Any]) -> A2ASendMessageResponse:
        """Parse a SendMessage response into the typed model.

        The response contains either a ``task`` or ``message`` key.
        """
        task = None
        message = None

        if "task" in data:
            task = A2ATask(**data["task"])
        if "message" in data:
            message = A2AMessage(**data["message"])

        return A2ASendMessageResponse(task=task, message=message)

    @staticmethod
    def _build_response_metadata(response: A2ASendMessageResponse) -> dict[str, Any]:
        """Build metadata dict from the response."""
        metadata: dict[str, Any] = {"protocol": "a2a"}

        if response.task:
            metadata["task_id"] = response.task.id
            metadata["context_id"] = response.task.context_id
            metadata["task_state"] = response.task.status.state
            metadata["is_terminal"] = response.task.is_terminal
            metadata["input_required"] = response.task.is_input_required
            metadata["auth_required"] = response.task.is_auth_required
        elif response.message:
            metadata["message_id"] = response.message.message_id

        return metadata

    @staticmethod
    def _extract_tool_calls(response: A2ASendMessageResponse) -> list[dict[str, Any]]:
        """Extract structured data from artifacts as 'tool call' equivalents.

        A2A doesn't expose tool calls directly (opacity principle), but
        structured JSON data in artifacts can be treated as tool outputs.
        """
        tool_calls: list[dict[str, Any]] = []
        if not response.task:
            return tool_calls

        for artifact in response.task.artifacts:
            for part in artifact.parts:
                if part.data:
                    tool_calls.append(
                        {
                            "name": artifact.name or artifact.artifact_id,
                            "output": part.data,
                        }
                    )
                elif part.media_type and part.media_type == "application/json" and part.text:
                    try:
                        parsed = json.loads(part.text)
                        tool_calls.append(
                            {
                                "name": artifact.name or artifact.artifact_id,
                                "output": parsed,
                            }
                        )
                    except json.JSONDecodeError:
                        pass

        return tool_calls
