"""Example: Dynamic attack vector generation from agent capabilities.

Demonstrates how the DynamicVectorGenerator creates tailored attack
vectors based on the tools and capabilities an agent exposes.  No
API keys required — capabilities are constructed manually.

What this example shows
-----------------------
  1. Creating AgentCapability objects manually
  2. Generating targeted vectors from capabilities
  3. Showing how tool combinations produce exfiltration-chain vectors
  4. Using a custom config to extend the generator

Usage::

    uv run python examples/dynamic_vectors_example.py
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ziran.application.dynamic_vectors.generator import DynamicVectorGenerator
from ziran.domain.entities.capability import AgentCapability, CapabilityType

console = Console()


def print_vectors(vectors: list, title: str) -> None:
    """Pretty-print generated vectors."""
    table = Table(title=title, show_lines=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("ID", style="cyan", max_width=32)
    table.add_column("Name", style="white", max_width=35)
    table.add_column("Category", style="magenta", max_width=20)
    table.add_column("Severity", width=8)
    table.add_column("Prompts", justify="right", width=7)

    severity_colors = {
        "critical": "[bold red]",
        "high": "[red]",
        "medium": "[yellow]",
        "low": "[blue]",
    }

    for i, v in enumerate(vectors, 1):
        sev = f"{severity_colors.get(v.severity, '')}{v.severity}"
        table.add_row(
            str(i),
            v.id,
            v.name,
            v.category.value,
            sev,
            str(v.prompt_count),
        )

    console.print(table)


def main() -> None:
    # ── 1. A simple agent with just a search tool ───────────────
    console.rule("[bold cyan]1. Simple agent — one search tool")

    simple_caps = [
        AgentCapability(
            id="search_docs",
            name="search_docs",
            type=CapabilityType.TOOL,
            description="Search the knowledge base",
        ),
    ]

    gen = DynamicVectorGenerator()
    simple_vectors = gen.generate(simple_caps)
    console.print(f"  Capabilities: {len(simple_caps)}")
    console.print(f"  Vectors generated: [bold]{len(simple_vectors)}[/bold]")
    print_vectors(simple_vectors, "Simple agent — generated vectors")

    # ── 2. A dangerous agent — shell + file + email ─────────────
    console.rule("[bold cyan]2. Dangerous agent — shell + file + email tools")

    dangerous_caps = [
        AgentCapability(
            id="run_shell",
            name="run_shell",
            type=CapabilityType.TOOL,
            description="Execute shell commands",
            dangerous=True,
        ),
        AgentCapability(
            id="read_file",
            name="read_file",
            type=CapabilityType.TOOL,
            description="Read files from the filesystem",
        ),
        AgentCapability(
            id="send_email",
            name="send_email",
            type=CapabilityType.TOOL,
            description="Send emails to any address",
        ),
        AgentCapability(
            id="query_database",
            name="query_database",
            type=CapabilityType.TOOL,
            description="Query the SQL database",
        ),
    ]

    dangerous_vectors = gen.generate(dangerous_caps)
    console.print(f"  Capabilities: {len(dangerous_caps)}")
    console.print(f"  Vectors generated: [bold]{len(dangerous_vectors)}[/bold]")
    print_vectors(dangerous_vectors, "Dangerous agent — generated vectors")

    # ── 3. Highlight exfiltration chains ────────────────────────
    console.rule("[bold cyan]3. Exfiltration chain vectors")

    exfil_vectors = [
        v for v in dangerous_vectors if "exfil" in v.id.lower() or "chain" in v.id.lower()
    ]
    if exfil_vectors:
        print_vectors(exfil_vectors, "Cross-tool exfiltration chains")
    else:
        console.print("  [dim]No exfiltration chains generated (tools may not match reader+sender pattern)[/dim]")

    # Show all categories generated
    categories = {v.category.value for v in dangerous_vectors}
    console.print(f"\n  Attack categories covered: {', '.join(sorted(categories))}")

    console.print("\n[green bold]✓ Dynamic vector example complete.[/green bold]\n")


if __name__ == "__main__":
    main()
