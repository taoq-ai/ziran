"""Web UI configuration via environment variables."""

from __future__ import annotations

import os

from pydantic import BaseModel


class WebUIConfig(BaseModel):
    """Configuration for the web UI server.

    Values are loaded from environment variables where available.
    """

    database_url: str = "postgresql+asyncpg://localhost:5432/ziran"
    host: str = "127.0.0.1"
    port: int = 8484
    dev_mode: bool = False

    @classmethod
    def from_env(cls) -> WebUIConfig:
        """Create config from environment variables."""
        return cls(
            database_url=os.environ.get(
                "ZIRAN_DATABASE_URL",
                "postgresql+asyncpg://localhost:5432/ziran",
            ),
            host=os.environ.get("ZIRAN_HOST", "127.0.0.1"),
            port=int(os.environ.get("ZIRAN_PORT", "8484")),
            dev_mode=os.environ.get("ZIRAN_DEV_MODE", "").lower() in ("1", "true", "yes"),
        )
