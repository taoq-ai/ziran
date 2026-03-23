"""Integration tests for the FastAPI web application."""

from __future__ import annotations

import pytest

from ziran.interfaces.web.app import create_app


@pytest.mark.integration
class TestCreateApp:
    def test_returns_fastapi_instance(self) -> None:
        from fastapi import FastAPI

        app = create_app()
        assert isinstance(app, FastAPI)

    def test_has_api_routes(self) -> None:
        app = create_app()
        paths = [route.path for route in app.routes]
        assert "/api/health" in paths


@pytest.mark.integration
class TestSPAFallback:
    def test_unknown_route_returns_html(self) -> None:
        from fastapi.testclient import TestClient

        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/some/unknown/route")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_root_returns_html(self) -> None:
        from fastapi.testclient import TestClient

        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
