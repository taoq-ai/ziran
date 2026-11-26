"""Port for the A2A identity probes (spec 118): raw A2A requests sent as a chosen client."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, Field

from ziran.domain.entities.target import A2AConfig, TargetConfig

A2AClient = Literal["target", "peer", "replay", "anonymous"]
"""``target`` carries the target's auth and headers; ``peer`` and ``replay`` carry only
``a2a.peer_auth`` or ``a2a.replay_auth``; ``anonymous`` carries no credential."""


class A2AReply(BaseModel):
    """One request's answer: HTTP status (0 when none came), the JSON result (a JSON-RPC
    ``result`` unwrapped), the raw body, and the error that stopped it, if any."""

    status: int = 0
    body: dict[str, Any] = Field(default_factory=dict)
    text: str = ""
    error: str | None = None

    @property
    def accepted(self) -> bool:
        return 200 <= self.status < 300 and self.error is None


class A2AWire(ABC):
    """Sends the probes' requests to one A2A target."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self.a2a = config.a2a or A2AConfig()

    @property
    def card_url(self) -> str:
        return (
            self.a2a.agent_card_url or f"{self.config.normalized_url}/.well-known/agent-card.json"
        )

    @abstractmethod
    async def get(self, url: str, client: A2AClient = "anonymous") -> A2AReply:
        """GET *url* (a card or a JWKS)."""

    @abstractmethod
    async def send(
        self, client: A2AClient, text: str, *, context_id: str, task_id: str | None = None
    ) -> A2AReply:
        """``SendMessage`` with one text part in *context_id* (and *task_id*)."""

    @abstractmethod
    async def get_task(self, client: A2AClient, task_id: str) -> A2AReply:
        """``GetTask`` for *task_id*, with its history."""
