"""CLI subcommand ``ziran mcp-hostile-server`` (spec 071).

Runs a hostile MCP server over stdio. Register it in an agent host's MCP config, ask
the host to call its ``lookup_glossary`` tool, then read the findings with
``ziran report``. stdout carries JSON-RPC only, so every message goes to stderr.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import click
from rich.console import Console

from ziran.application.attacks.library import AttackLibrary
from ziran.application.mcp_server_surface.scoring import build_campaign_result
from ziran.domain.entities.mcp_server_surface import McpHostileRecord
from ziran.interfaces.cli.reports import ReportGenerator

console = Console(stderr=True)

RECORD_FILE = "mcp_hostile_record.json"
FAMILIES = (
    "sampling-injection",
    "elicitation-phishing",
    "elicitation-overbroad",
    "roots-capability-creep",
)


@click.command("mcp-hostile-server")
@click.option(
    "--vector",
    "vector_ids",
    multiple=True,
    help="Server-surface vector ID to send (repeatable). Default: all of them.",
)
@click.option(
    "--family",
    "families",
    multiple=True,
    type=click.Choice(FAMILIES),
    help="Sub-family to send (repeatable). Adds to --vector.",
)
@click.option(
    "--record-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Folder for the record and the CampaignResult JSON.",
)
@click.option(
    "--timeout",
    type=click.FloatRange(min=1),
    default=120.0,
    show_default=True,
    help="Seconds to wait for each client reply (a person may answer a form).",
)
def mcp_hostile_server(
    vector_ids: tuple[str, ...],
    families: tuple[str, ...],
    record_dir: Path,
    timeout: float,
) -> None:
    """Act as a hostile MCP server over stdio and score the client's replies.

    \b
    Example MCP config entry:
        {"command": "ziran", "args": ["mcp-hostile-server", "--record-dir", "/abs/dir"]}
    """
    surface = [v for v in AttackLibrary().vectors if v.mcp_server_request is not None]
    unknown = sorted(set(vector_ids) - {v.id for v in surface})
    if unknown:
        raise click.BadParameter(
            f"not a server-surface vector: {', '.join(unknown)}", param_hint="--vector"
        )
    pick_all = not vector_ids and not families
    selected = [
        v for v in surface if pick_all or v.id in vector_ids or any(f in v.tags for f in families)
    ]
    if not selected:
        raise click.UsageError("no server-surface vectors selected")
    try:
        from ziran.infrastructure.mcp_hostile.server import build_server
    except ImportError as exc:
        console.print("[red]The MCP SDK is not installed.[/red] Run: pip install 'ziran\\[mcp]'")
        raise SystemExit(1) from exc

    record_dir.mkdir(parents=True, exist_ok=True)
    campaign_id = f"mcp-hostile-{uuid.uuid4().hex[:12]}"
    reports = ReportGenerator(output_dir=record_dir)

    def write(record: McpHostileRecord) -> None:
        path = record_dir / RECORD_FILE
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record.model_dump(mode="json"), indent=2))
        os.replace(tmp, path)
        reports.save_json(build_campaign_result(selected, record, campaign_id=campaign_id))

    record = McpHostileRecord()
    write(record)  # a host that never calls the tool still leaves an all-unmeasured result
    console.print(
        f"[dim]mcp-hostile-server: {len(selected)} vector(s), record in {record_dir}[/dim]"
    )
    try:
        build_server(selected, record, on_update=write, timeout=timeout).run("stdio")
    finally:
        write(record)
        console.print(f"[dim]mcp-hostile-server: wrote {record_dir / RECORD_FILE}[/dim]")
