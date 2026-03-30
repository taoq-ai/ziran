"""Alembic environment — synchronous migrations (safe inside async event loops)."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from ziran.interfaces.web.models import Base

# Alembic Config object (set programmatically by app.py).
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _sync_url(url: str) -> str:
    """Convert an async DB URL to a sync one for Alembic migrations.

    postgresql+asyncpg://... → postgresql://...
    """
    return url.replace("+asyncpg", "")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL only)."""
    url = _sync_url(config.get_main_option("sqlalchemy.url", ""))
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using a sync engine.

    This avoids ``asyncio.run()`` conflicts when called from within
    an already-running event loop (e.g. uvicorn lifespan).
    """
    url = _sync_url(config.get_main_option("sqlalchemy.url", ""))
    connectable = create_engine(url, poolclass=None)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
