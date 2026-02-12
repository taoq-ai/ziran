"""Generating Proof-of-Concept exploit scripts.

Create standalone exploit scripts from attack results. No API
keys required — uses synthetic attack results.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax

from ziran.application.poc.generator import PoCGenerator
from ziran.domain.entities.phase import CampaignResult

from fixtures import (
    DATA_EXFIL_RESULT,
    PROMPT_INJECTION_RESULT,
    ROLE_PLAY_RESULT,
)

console = Console()


def main() -> None:
    output = Path(tempfile.mkdtemp(prefix="ziran_pocs_"))
    gen = PoCGenerator(output_dir=output)

    # ── 1. Generate a Python PoC ────────────────────────────────
    console.rule("[bold cyan]1. Python PoC script")
    py_path = gen.generate_python_poc(PROMPT_INJECTION_RESULT, "campaign_demo")
    console.print(f"  Generated: [cyan]{py_path}[/cyan]")
    content = py_path.read_text()
    console.print(Syntax(content[:1500], "python", line_numbers=True, theme="monokai"))

    # ── 2. Generate a cURL PoC ──────────────────────────────────
    console.rule("[bold cyan]2. cURL PoC script")
    curl_path = gen.generate_curl_poc(
        DATA_EXFIL_RESULT,
        endpoint="http://localhost:8000/chat",
        campaign_id="campaign_demo",
    )
    console.print(f"  Generated: [cyan]{curl_path}[/cyan]")
    console.print(Syntax(curl_path.read_text()[:800], "bash", line_numbers=True, theme="monokai"))

    # ── 3. Generate Markdown guide ──────────────────────────────
    console.rule("[bold cyan]3. Markdown reproduction guide")
    md_path = gen.generate_markdown_guide(
        [PROMPT_INJECTION_RESULT, DATA_EXFIL_RESULT],
        campaign_id="campaign_demo",
    )
    console.print(f"  Generated: [cyan]{md_path}[/cyan]")
    preview_lines = md_path.read_text().splitlines()[:40]
    console.print(Syntax("\n".join(preview_lines), "markdown", theme="monokai"))

    # ── 4. Generate all from CampaignResult ─────────────────────
    console.rule("[bold cyan]4. generate_all() from CampaignResult")

    campaign = CampaignResult(
        campaign_id="campaign_full_demo",
        target_agent="vulnerable_helpdesk",
        phases_executed=[],
        attack_results=[
            PROMPT_INJECTION_RESULT.model_dump(mode="json"),
            DATA_EXFIL_RESULT.model_dump(mode="json"),
            ROLE_PLAY_RESULT.model_dump(mode="json"),
        ],
        total_vulnerabilities=2,
        final_trust_score=0.3,
        success=True,
    )

    all_paths = gen.generate_all(campaign)
    console.print(f"  Files generated: [bold]{len(all_paths)}[/bold]")
    for p in all_paths:
        console.print(f"    {p.suffix:5s} → [cyan]{p.name}[/cyan]")

    # ── Cleanup ─────────────────────────────────────────────────
    shutil.rmtree(output)

    console.print("\n[green bold]✓ PoC generation example complete.[/green bold]\n")


if __name__ == "__main__":
    main()
