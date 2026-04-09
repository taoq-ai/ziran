"""CLI subcommand for MCP registry drift watching.

Monitors MCP server registries for manifest drift, tool changes,
and typosquat attacks.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.table import Table

from ziran.application.registry_watch.watcher_service import watch
from ziran.domain.entities.registry import DriftFinding, RegistryConfig, ServerEntry
from ziran.infrastructure.snapshot_stores.json_file_store import JsonFileStore

logger = logging.getLogger(__name__)
console = Console()

# ──────────────────────────────────────────────────────────────────────
# Default HTTP fetcher
# ──────────────────────────────────────────────────────────────────────


class HttpManifestFetcher:
    """Fetch MCP manifests over HTTP using JSON-RPC 2.0."""

    async def fetch(self, server: ServerEntry) -> dict[str, Any]:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            tools_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            resp = await client.post(server.url, json=tools_payload)
            resp.raise_for_status()
            tools_result = resp.json().get("result", {})

            resources_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/list",
                "params": {},
            }
            try:
                resp2 = await client.post(server.url, json=resources_payload)
                resp2.raise_for_status()
                resources_result = resp2.json().get("result", {})
            except Exception:
                resources_result = {}

            prompts_payload = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "prompts/list",
                "params": {},
            }
            try:
                resp3 = await client.post(server.url, json=prompts_payload)
                resp3.raise_for_status()
                prompts_result = resp3.json().get("result", {})
            except Exception:
                prompts_result = {}

            return {
                "tools": tools_result.get("tools", []),
                "resources": resources_result.get("resources", []),
                "prompts": prompts_result.get("prompts", []),
            }


# ──────────────────────────────────────────────────────────────────────
# Report helpers
# ──────────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


def _write_json_report(findings: list[DriftFinding], path: Path) -> None:
    data = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _write_markdown_report(findings: list[DriftFinding], path: Path) -> None:
    lines = ["# Registry Watch Report\n"]
    if not findings:
        lines.append("No drift detected.\n")
    else:
        lines.append(f"**{len(findings)} finding(s) detected.**\n")
        for f in findings:
            lines.append(f"## {f.drift_type} — {f.server_name}\n")
            lines.append(f"- **Severity:** {f.severity}")
            if f.tool_name:
                lines.append(f"- **Tool:** {f.tool_name}")
            lines.append(f"- **Message:** {f.message}")
            if f.previous_value:
                lines.append(f"- **Previous:** {f.previous_value}")
            if f.current_value:
                lines.append(f"- **Current:** {f.current_value}")
            if f.suspected_canonical:
                lines.append(f"- **Suspected canonical:** {f.suspected_canonical}")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _print_summary(findings: list[DriftFinding]) -> None:
    if not findings:
        console.print("[green]No drift detected.[/green]")
        return

    table = Table(title="Registry Watch Findings")
    table.add_column("Server", style="bold")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Tool")
    table.add_column("Message")

    for f in findings:
        severity_style = _SEVERITY_COLORS.get(f.severity, "")
        table.add_row(
            f.server_name,
            f.drift_type,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            f.tool_name or "-",
            f.message,
        )

    console.print(table)
    console.print(f"\n[bold]{len(findings)} finding(s) total.[/bold]")


# ──────────────────────────────────────────────────────────────────────
# Click command
# ──────────────────────────────────────────────────────────────────────


@click.command("watch-registry")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to registry config YAML file.",
)
@click.option(
    "--snapshot-dir",
    type=click.Path(path_type=Path),
    default=Path(".ziran/snapshots"),
    show_default=True,
    help="Directory for storing manifest snapshots.",
)
@click.option(
    "--out",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./reports"),
    show_default=True,
    help="Output directory for findings reports.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"]),
    default="json",
    show_default=True,
    help="Report output format.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def watch_registry(
    config_path: Path,
    snapshot_dir: Path,
    output_dir: Path,
    output_format: str,
    verbose: bool,
) -> None:
    """Monitor MCP server registries for drift and typosquatting."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Load config
    raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    registry_config = RegistryConfig.model_validate(raw_config)

    # Override snapshot dir if specified in config
    if registry_config.snapshot_dir:
        snapshot_dir = Path(registry_config.snapshot_dir)

    store = JsonFileStore(snapshot_dir)
    fetcher = HttpManifestFetcher()

    findings = asyncio.run(watch(registry_config, store, fetcher))

    # Write report
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = "json" if output_format == "json" else "md"
    report_path = output_dir / f"registry-watch-report.{ext}"

    if output_format == "json":
        _write_json_report(findings, report_path)
    else:
        _write_markdown_report(findings, report_path)

    console.print(f"Report written to [bold]{report_path}[/bold]")
    _print_summary(findings)

    # Exit with non-zero if critical/high findings exist
    high_or_critical = [f for f in findings if f.severity in ("critical", "high")]
    if high_or_critical:
        raise SystemExit(1)
