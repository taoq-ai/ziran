"""FastAPI application factory for the ziran web dashboard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles

from ziran.interfaces.web.config import WebUIConfig
from ziran.interfaces.web.dependencies import init_db
from ziran.interfaces.web.routes.compliance import router as compliance_router
from ziran.interfaces.web.routes.export import router as export_router
from ziran.interfaces.web.routes.findings import router as findings_router
from ziran.interfaces.web.routes.health import router as health_router
from ziran.interfaces.web.routes.runs import router as runs_router
from ziran.interfaces.web.routes.ws import router as ws_router

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

_FALLBACK_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Ziran Web UI</title></head>
<body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;\
align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1>Ziran Web UI</h1>
<p>Frontend assets not found. Build the UI or install with:
<code>pip install ziran[ui]</code></p>
</div>
</body>
</html>
"""


def _run_migrations(database_url: str) -> None:
    """Run Alembic migrations to ``head``."""
    from alembic import command
    from alembic.config import Config

    migrations_dir = str(Path(__file__).parent / "migrations")

    cfg = Config()
    cfg.set_main_option("script_location", migrations_dir)
    cfg.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(cfg, "head")


def create_app(
    config: WebUIConfig | None = None,
    *,
    dev: bool = False,
) -> FastAPI:
    """Build and return the FastAPI application.

    Parameters
    ----------
    config:
        Optional pre-built config.  When *None*, loads from env.
    dev:
        Enable CORS for all origins (dev workflow).
    """
    if config is None:
        config = WebUIConfig.from_env()
    if dev:
        config = config.model_copy(update={"dev_mode": True})

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        from ziran.interfaces.web.services.run_manager import RunManager

        # Run Alembic migrations synchronously (Alembic handles its own async engine).
        try:
            _run_migrations(config.database_url)
        except Exception:
            logger.exception("Failed to run database migrations")
            raise

        # Initialise the async session factory used by DI.
        session_factory = init_db(config)

        # Create and store RunManager on app state.
        app.state.run_manager = RunManager(session_factory)

        yield

        # Shutdown: cancel all active scans.
        await app.state.run_manager.shutdown()

    app = FastAPI(
        title="Ziran Web UI",
        lifespan=lifespan,
    )

    # --- CORS (dev mode only) ---
    if config.dev_mode:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- API routes ---
    app.include_router(health_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    app.include_router(findings_router, prefix="/api")
    app.include_router(compliance_router, prefix="/api")
    app.include_router(export_router, prefix="/api")

    # --- WebSocket ---
    app.include_router(ws_router)

    # --- Static files (built React assets) ---
    index_html: str | None = None
    if _STATIC_DIR.is_dir() and (_STATIC_DIR / "index.html").exists():
        index_html = (_STATIC_DIR / "index.html").read_text()
        app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    # --- SPA fallback ---
    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    async def spa_fallback(full_path: str) -> HTMLResponse:
        return HTMLResponse(index_html if index_html else _FALLBACK_HTML)

    return app
