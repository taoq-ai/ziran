"""Custom hatch build hook — compiles the React frontend before wheel packaging."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

logger = logging.getLogger(__name__)


class FrontendBuildHook(BuildHookInterface):
    """Run ``npm ci && npm run build`` in ``ui/`` if Node.js is available."""

    PLUGIN_NAME = "frontend"

    def initialize(self, version: str, build_data: dict) -> None:  # type: ignore[override]
        ui_dir = Path(self.root) / "ui"
        if not ui_dir.is_dir():
            logger.info("ui/ directory not found — skipping frontend build")
            return

        node = shutil.which("node")
        npm = shutil.which("npm")
        if not node or not npm:
            logger.warning(
                "Node.js/npm not found — skipping frontend build. "
                "The wheel will not contain pre-built UI assets."
            )
            return

        logger.info("Building frontend in %s", ui_dir)
        try:
            subprocess.run(
                [npm, "ci"],
                cwd=str(ui_dir),
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [npm, "run", "build"],
                cwd=str(ui_dir),
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info("Frontend build complete")
        except subprocess.CalledProcessError as exc:
            logger.error("Frontend build failed:\n%s", exc.stderr)
            raise
