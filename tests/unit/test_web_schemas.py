"""Tests for Pydantic web UI schemas."""

from __future__ import annotations

import pytest

from ziran import __version__
from ziran.interfaces.web.schemas import HealthResponse


@pytest.mark.unit
class TestHealthResponse:
    def test_serialization(self) -> None:
        resp = HealthResponse(status="ok", database="connected")
        data = resp.model_dump()
        assert data["status"] == "ok"
        assert data["version"] == __version__
        assert data["database"] == "connected"

    def test_degraded_status(self) -> None:
        resp = HealthResponse(status="degraded", database="disconnected")
        assert resp.status == "degraded"
        assert resp.database == "disconnected"

    def test_version_default(self) -> None:
        resp = HealthResponse(status="ok", database="connected")
        assert resp.version == __version__
