"""The React frontend and its Node.js build are gone (spec 084, #521)."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def _steps(workflow: Path) -> list[dict[str, Any]]:
    jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]
    return [step for job in jobs.values() for step in job.get("steps", [])]


@pytest.mark.unit
def test_frontend_sources_and_build_hook_are_gone() -> None:
    assert not (ROOT / "ui").exists()
    assert not (ROOT / "hatch_build.py").exists()
    assert not (ROOT / "docker-compose.yml").exists()
    hooks = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["hatch"]["build"]["hooks"]
    assert "custom" not in hooks


@pytest.mark.unit
@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_step_needs_node_or_ui(workflow: Path) -> None:
    for step in _steps(workflow):
        assert not str(step.get("uses", "")).startswith("actions/setup-node"), step
        assert "npm" not in str(step.get("run", "")), step
        assert step.get("working-directory") != "ui", step
        assert "ui/" not in str(step.get("run", "")), step


@pytest.mark.unit
def test_playwright_install_stays_for_the_browser_adapter() -> None:
    runs = [str(s.get("run", "")) for s in _steps(ROOT / ".github" / "workflows" / "test.yml")]
    assert any("playwright install chromium" in run for run in runs)


@pytest.mark.unit
def test_dependabot_has_no_npm_entry() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert [u for u in config["updates"] if u["package-ecosystem"] == "npm"] == []


@pytest.mark.unit
def test_dockerfile_is_a_cli_image() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert [line for line in dockerfile.splitlines() if line.startswith("FROM ")] == [
        "FROM python:3.12-slim"
    ]
    assert 'ENTRYPOINT ["ziran"]' in dockerfile
    for gone in ("node", "npm", "[ui]", "ZIRAN_DATABASE_URL", "interfaces/web"):
        assert gone not in dockerfile
