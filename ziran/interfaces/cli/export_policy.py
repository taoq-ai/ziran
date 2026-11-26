"""CLI command for exporting guardrail policies from scan results."""

from __future__ import annotations

import json
import re
from pathlib import Path

import click
from rich.console import Console

from ziran.application.policy_export.export_service import ExportService
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.entities.policy import GuardrailPolicyFormat
from ziran.infrastructure.policy_renderers import (
    CedarRenderer,
    ColangRenderer,
    InvariantRenderer,
    RegoRenderer,
    SigmaRenderer,
)
from ziran.interfaces.cli._text import term

console = Console()

_FORMAT_EXT: dict[str, str] = {
    "rego": ".rego",
    "cedar": ".cedar",
    "nemo": ".co",
    "invariant": ".invariant",
    "sigma": ".yml",
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
    type=click.Choice(["rego", "cedar", "nemo", "invariant", "sigma"]),
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
    "--exclude-probes",
    is_flag=True,
    default=False,
    help="Sigma only: leave out spans in this scan's probe trace ids (probe_markers).",
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
    exclude_probes: bool,
    verbose: bool,
) -> None:
    """Export scan findings as runtime guardrail policies or Sigma detection rules."""
    if exclude_probes and fmt != "sigma":
        raise click.UsageError("--exclude-probes applies only to --format sigma")
    campaign = CampaignResult.model_validate(json.loads(result.read_text(encoding="utf-8")))
    renderer = (
        SigmaRenderer(campaign, exclude_probes=exclude_probes)
        if fmt == "sigma"
        else _FORMAT_TO_RENDERER[fmt]()
    )
    policies = ExportService(renderer).export(campaign, severity_floor)

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
                    f"[dim]SKIP {term(policy.finding_id)}: {term(policy.skip_reason)}[/dim]",
                )
            continue

        # finding_id carries the result file's campaign_id: keep it one name inside --out
        file_path = out / f"{re.sub(r'[^A-Za-z0-9._-]', '_', policy.finding_id)}{ext}"
        file_path.write_text(policy.content, encoding="utf-8")
        written += 1
        if verbose:
            console.print(
                f"[green]WRITE[/green] {term(file_path)}",
            )

    # Map CLI format name to the enum for display
    display_format = GuardrailPolicyFormat.COLANG if fmt == "nemo" else fmt
    console.print(
        f"[bold green]Exported {written} {display_format} policies[/bold green] to {out}",
    )
    if skipped:
        why = (
            "not proven by a recorded attack, or failed the self-check"
            if fmt == "sigma"
            else f"not expressible in {display_format}"
        )
        console.print(f"[yellow]{skipped} chains skipped ({why})[/yellow]")
