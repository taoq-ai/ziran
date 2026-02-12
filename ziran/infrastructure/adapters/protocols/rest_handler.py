"""Generic REST protocol handler.

Sends messages to arbitrary REST endpoints with configurable
request/response JSON field paths. Suitable for custom agent APIs
that don't follow a standard protocol.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ziran.domain.entities.target import TargetConfig
from ziran.infrastructure.adapters.protocols import BaseProtocolHandler, ProtocolError

logger = logging.getLogger(__name__)


class RestProtocolHandler(BaseProtocolHandler):
    """Handler for generic REST API agents.

    Sends ``POST`` (or configured method) requests with the prompt in
    a configurable JSON field and extracts the response from a
    configurable response field.
    """

    def __init__(self, client: httpx.AsyncClient, config: TargetConfig) -> None:
        super().__init__(client, config)
        self._rest = config.rest or _default_rest()

    async def send(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a message via REST API.

        Args:
            message: The prompt text to send.

        Returns:
            Dict with ``content``, ``tool_calls``, and ``metadata``.

        Raises:
            ProtocolError: On HTTP or parsing errors.
        """
        url = self._config.normalized_url
        if self._rest.request_path:
            url = f"{url}/{self._rest.request_path.lstrip('/')}"

        body: dict[str, Any] = {self._rest.message_field: message}
        body.update(self._rest.extra_body)

        try:
            response = await self._client.request(
                method=self._rest.method,
                url=url,
                json=body,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"REST request failed with status {exc.response.status_code}"
            raise ProtocolError(msg, status_code=exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            msg = f"REST request failed: {exc}"
            raise ProtocolError(msg) from exc

        data = response.json()
        content = _extract_field(data, self._rest.response_field)

        return {
            "content": content,
            "tool_calls": [],
            "metadata": {"raw_response": data, "protocol": "rest"},
        }

    async def discover(self) -> list[dict[str, Any]]:
        """REST APIs don't have a standard discovery mechanism.

        Returns an empty list — the HttpAgentAdapter will fall back
        to probe-based discovery.
        """
        return []

    async def health_check(self) -> bool:
        """Check if the REST endpoint is reachable."""
        try:
            url = self._config.normalized_url
            if self._rest.request_path:
                url = f"{url}/{self._rest.request_path.lstrip('/')}"
            resp = await self._client.request(
                method="HEAD" if self._rest.method == "GET" else "OPTIONS",
                url=url,
            )
            return resp.status_code < 500
        except httpx.HTTPError:
            return False


def _extract_field(data: Any, field_path: str) -> str:
    """Extract a value from nested JSON using dot-separated path.

    Args:
        data: Parsed JSON response.
        field_path: Dot-separated path (e.g. ``result.text``).

    Returns:
        String value at the path, or str(data) as fallback.
    """
    current = data
    for key in field_path.split("."):
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return str(data) if not isinstance(data, str) else data
    return str(current)


def _default_rest() -> Any:  # noqa: ANN401
    """Create default RestConfig (avoids circular import at module level)."""
    from ziran.domain.entities.target import RestConfig

    return RestConfig()
