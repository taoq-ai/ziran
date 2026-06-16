"""Integration tests for the FastAPI web application."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ziran.interfaces.web.app import create_app

if TYPE_CHECKING:
    from fastapi import FastAPI


def _registered_paths(app: FastAPI) -> list[str]:
    """Collect route paths robustly across FastAPI versions.

    FastAPI <0.136 flattens included routers into ``app.routes`` (full paths like
    ``/api/health``); FastAPI >=0.136 inserts ``_IncludedRouter`` proxies whose
    sub-routes live on ``.original_router.routes`` with prefix-relative paths
    (``/health``). Collect both so callers can match on path suffixes.
    """
    paths: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if isinstance(path, str):
            paths.append(path)
        original = getattr(route, "original_router", None)
        if original is not None:
            for sub in getattr(original, "routes", []):
                sub_path = getattr(sub, "path", None)
                if isinstance(sub_path, str):
                    paths.append(sub_path)
    return paths


@pytest.mark.integration
class TestCreateApp:
    def test_returns_fastapi_instance(self) -> None:
        from fastapi import FastAPI

        app = create_app()
        assert isinstance(app, FastAPI)

    def test_has_api_routes(self) -> None:
        paths = _registered_paths(create_app())
        for suffix in ("/health", "/runs", "/runs/{run_id}", "/runs/{run_id}/cancel"):
            assert any(p.endswith(suffix) for p in paths), f"missing route: {suffix}"

    def test_has_websocket_route(self) -> None:
        paths = _registered_paths(create_app())
        assert any(p.endswith("/ws/runs/{run_id}") for p in paths)


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
