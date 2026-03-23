"""Pydantic request/response schemas for the web UI API."""

from __future__ import annotations

from pydantic import BaseModel

from ziran import __version__


class HealthResponse(BaseModel):
    """Response for GET /api/health."""

    status: str
    version: str = __version__
    database: str
