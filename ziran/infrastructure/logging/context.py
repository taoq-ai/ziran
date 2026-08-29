"""Log context binding via structlog contextvars.

Thin wrappers over :mod:`structlog.contextvars` so the scanner layers can bind
``campaign_id``, ``phase``, and ``vector_id`` once and have them merged into
every log line emitted within that async context.
"""

from __future__ import annotations

import structlog


def bind_campaign(campaign_id: str) -> None:
    """Bind the campaign id onto the current context."""
    structlog.contextvars.bind_contextvars(campaign_id=campaign_id)


def bind_phase(phase: str) -> None:
    """Bind the current scan phase onto the context."""
    structlog.contextvars.bind_contextvars(phase=phase)


def bind_vector(vector_id: str) -> None:
    """Bind the current attack vector id onto the context."""
    structlog.contextvars.bind_contextvars(vector_id=vector_id)


def clear_context() -> None:
    """Clear all bound context fields."""
    structlog.contextvars.clear_contextvars()
