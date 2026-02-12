"""OpenAI-compatible protocol handler.

Communicates with any agent or LLM exposing an OpenAI-compatible
``/v1/chat/completions`` endpoint — including Azure OpenAI, vLLM,
Ollama, LiteLLM proxies, and similar.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

if TYPE_CHECKING:
    from ziran.domain.entities.target import TargetConfig

logger = logging.getLogger(__name__)

# Default model to request if none is specified in headers/body
_DEFAULT_MODEL = "gpt-4"


class OpenAIProtocolHandler(BaseProtocolHandler):
    """Handler for OpenAI-compatible chat completions API."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: TargetConfig,
        model: str = _DEFAULT_MODEL,
    ) -> None:
        super().__init__(client, config)
        self._model = model
        self._conversation: list[dict[str, str]] = []

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a message via the chat completions endpoint.

        Maintains conversation history for multi-turn interactions.

        Args:
            message: The user prompt.

        Returns:
            Dict with ``content``, ``tool_calls``, and ``metadata``.
        """
        self._conversation.append({"role": "user", "content": message})

        url = f"{self._config.normalized_url}/v1/chat/completions"
        body: dict[str, Any] = {
            "model": self._model,
            "messages": list(self._conversation),
        }

        try:
            response = await self._client.post(url, json=body)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"OpenAI request failed with status {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"OpenAI request failed: {exc}"
            raise ProtocolError(msg) from exc

        data = response.json()
        choice = data.get("choices", [{}])[0]
        assistant_message = choice.get("message", {})
        content = assistant_message.get("content", "")
        tool_calls_raw = assistant_message.get("tool_calls", [])

        # Track assistant response in conversation
        self._conversation.append({"role": "assistant", "content": content})

        # Parse tool calls
        tool_calls = []
        for tc in tool_calls_raw:
            tool_calls.append(
                {
                    "id": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "arguments": tc.get("function", {}).get("arguments", "{}"),
                }
            )

        # Extract token usage
        usage = data.get("usage", {})

        return {
            "content": content,
            "tool_calls": tool_calls,
            "metadata": {
                "model": data.get("model", self._model),
                "finish_reason": choice.get("finish_reason"),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "protocol": "openai",
            },
        }

    async def discover(self) -> list[dict[str, Any]]:
        """Discover available models via ``GET /v1/models``.

        Returns:
            List of model capability descriptors.
        """
        url = f"{self._config.normalized_url}/v1/models"
        try:
            response = await self._client.get(url)
            response.raise_for_status()
        except httpx.HTTPError:
            logger.debug("OpenAI model listing not available at %s", url)
            return []

        data = response.json()
        models = data.get("data", [])
        return [
            {
                "id": m.get("id", "unknown"),
                "name": m.get("id", "unknown"),
                "type": "model",
                "description": f"Model: {m.get('id', 'unknown')}",
                "owner": m.get("owned_by", ""),
            }
            for m in models
        ]

    async def health_check(self) -> bool:
        """Check if the OpenAI-compatible endpoint is reachable."""
        url = f"{self._config.normalized_url}/v1/models"
        try:
            resp = await self._client.get(url)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    def reset_conversation(self) -> None:
        """Clear the conversation history."""
        self._conversation.clear()
