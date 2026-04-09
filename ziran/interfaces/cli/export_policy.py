"""CLI command for exporting guardrail policies from scan results."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from ziran.application.policy_export.export_service import ExportService
from ziran.domain.entities.policy import GuardrailPolicyFormat
from ziran.infrastructure.policy_renderers import (
    CedarRenderer,
    ColangRenderer,
    InvariantRenderer,
    RegoRenderer,
)

console = Console()

_FORMAT_EXT: dict[str, str] = {
    "rego": ".rego",
    "cedar": ".cedar",
    "nemo": ".co",
    "invariant": ".invariant",
}

_FORMAT_TO_RENDERER: dict[
    str, type[RegoRenderer | CedarRenderer | ColangRenderer | InvariantRenderer]
] = {
    "rego": RegoRenderer,
    "cedar": CedarRenderer,
    "nemo": ColangRenderer,
    "invariant": InvariantRenderer,
}


@click.command("export-policy")
@click.option(
    "--result",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to a campaign result JSON file.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["rego", "cedar", "nemo", "invariant"]),
    required=True,
    help="Guardrail policy format to generate.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=Path("./policies/"),
    show_default=True,
    help="Output directory for policy files.",
)
@click.option(
    "--severity-floor",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="medium",
    show_default=True,
    help="Minimum severity to include.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Print extra detail while exporting.",
)
def export_policy(
    result: Path,
    fmt: str,
    out: Path,
    severity_floor: str,
    verbose: bool,
) -> None:
    """Export scan findings as runtime guardrail policies."""
    renderer_cls = _FORMAT_TO_RENDERER[fmt]
    renderer = renderer_cls()
    service = ExportService(renderer)

    policies = service.export_from_file(result, severity_floor)

    if not policies:
        console.print(
            "[yellow]No dangerous chains matched the severity floor. Nothing exported.[/yellow]",
        )
        return

    out.mkdir(parents=True, exist_ok=True)
    ext = _FORMAT_EXT[fmt]

    written = 0
    skipped = 0
    for policy in policies:
        if policy.skipped:
            skipped += 1
            if verbose:
                console.print(
                    f"[dim]SKIP {policy.finding_id}: {policy.skip_reason}[/dim]",
                )
            continue

        file_path = out / f"{policy.finding_id}{ext}"
        file_path.write_text(policy.content, encoding="utf-8")
        written += 1
        if verbose:
            console.print(
                f"[green]WRITE[/green] {file_path}",
            )

    # Map CLI format name to the enum for display
    display_format = GuardrailPolicyFormat.COLANG if fmt == "nemo" else fmt
    console.print(
        f"[bold green]Exported {written} {display_format} policies[/bold green] to {out}",
    )
    if skipped:
        console.print(
            f"[yellow]{skipped} chains skipped (not expressible in {display_format})[/yellow]",
        )
