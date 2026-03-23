"""FastAPI dependency injection providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from sqlalchemy.ext.asyncio import AsyncSession

    from ziran.interfaces.web.config import WebUIConfig

# Module-level state — initialised by ``init_db``.
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(config: WebUIConfig) -> None:
    """Create the async engine and session factory.

    Must be called once at application startup (inside the lifespan
    handler) before any request can use ``get_db``.
    """
    global _session_factory
    engine = create_async_engine(config.database_url, echo=False)
    _session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an ``AsyncSession`` for a single request."""
    if _session_factory is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    async with _session_factory() as session:
        yield session
