"""Browsing and filtering the ZIRAN attack vector library.

Explore 40+ built-in attack vectors and load custom vectors
from YAML. No API keys required.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import AttackCategory, OwaspLlmCategory
from ziran.domain.entities.phase import CoverageLevel, ScanPhase

console = Console()
HERE = Path(__file__).resolve().parent


def print_vectors(vectors: list, title: str, *, max_rows: int = 10) -> None:
    """Pretty-print attack vectors in a Rich table."""
    table = Table(title=title, show_lines=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("ID", style="cyan", max_width=30)
    table.add_column("Name", style="white", max_width=35)
    table.add_column("Category", style="magenta", max_width=18)
    table.add_column("Severity", width=8)
    table.add_column("Phase", style="dim", max_width=20)

    severity_colors = {
        "critical": "[bold red]",
        "high": "[red]",
        "medium": "[yellow]",
        "low": "[blue]",
    }

    for i, v in enumerate(vectors[:max_rows], 1):
        sev = f"{severity_colors.get(v.severity, '')}{v.severity}"
        table.add_row(str(i), v.id, v.name, v.category.value, sev, v.target_phase.value)

    if len(vectors) > max_rows:
        table.add_row("…", f"(+{len(vectors) - max_rows} more)", "", "", "", "")

    console.print(table)


def main() -> None:
    # ── 1. Load the built-in library ────────────────────────────
    console.rule("[bold cyan]1. Built-in attack library")
    library = AttackLibrary()
    console.print(f"  Total vectors : [bold]{library.vector_count}[/bold]")
    console.print(f"  Categories    : {', '.join(c.value for c in library.categories)}")

    # ── 2. Category breakdown ───────────────────────────────────
    console.rule("[bold cyan]2. Category breakdown")
    cat_table = Table(title="Vectors by category", show_lines=True)
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", justify="right")
    for cat in sorted(library.categories, key=lambda c: c.value):
        count = len(library.get_attacks_by_category(cat))
        cat_table.add_row(cat.value, str(count))
    console.print(cat_table)

    # ── 3. Filter by phase ──────────────────────────────────────
    console.rule("[bold cyan]3. Filter by phase — RECONNAISSANCE")
    recon = library.get_attacks_for_phase(ScanPhase.RECONNAISSANCE)
    print_vectors(recon, "Reconnaissance vectors")

    # ── 4. Coverage levels ──────────────────────────────────────
    console.rule("[bold cyan]4. Coverage levels — ESSENTIAL vs COMPREHENSIVE")
    essential = library.get_attacks_for_phase(ScanPhase.EXECUTION, coverage=CoverageLevel.ESSENTIAL)
    comprehensive = library.get_attacks_for_phase(
        ScanPhase.EXECUTION, coverage=CoverageLevel.COMPREHENSIVE
    )
    console.print(
        f"  EXECUTION phase: essential={len(essential)} vectors, "
        f"comprehensive={len(comprehensive)} vectors"
    )

    # ── 5. Filter by OWASP category ─────────────────────────────
    console.rule("[bold cyan]5. Filter by OWASP — LLM01 (Prompt Injection)")
    llm01 = library.get_attacks_by_owasp(OwaspLlmCategory.LLM01)
    print_vectors(llm01, "OWASP LLM01 vectors")

    # ── 6. Multi-criteria search ────────────────────────────────
    console.rule("[bold cyan]6. Multi-criteria search")
    results = library.search(
        category=AttackCategory.DATA_EXFILTRATION,
        severity="high",
    )
    print_vectors(results, "Data exfiltration (high severity)")

    # ── 7. Custom attack vectors from YAML ──────────────────────
    console.rule("[bold cyan]7. Custom attack vectors from YAML")

    custom_dir = HERE  # custom_vector.yaml lives alongside this script
    library_with_custom = AttackLibrary(custom_dirs=[custom_dir])
    console.print(f"  Total vectors (with custom): [bold]{library_with_custom.vector_count}[/bold]")

    custom_vec = library_with_custom.get_vector("corp_internal_auth_bypass")
    if custom_vec:
        console.print(f"  Custom vector loaded: [cyan]{custom_vec.name}[/cyan]")
        console.print(f"    Category  : {custom_vec.category.value}")
        console.print(f"    Severity  : {custom_vec.severity}")
        console.print(f"    OWASP     : {', '.join(o.value for o in custom_vec.owasp_mapping)}")
        console.print(f"    Prompts   : {custom_vec.prompt_count}")

    console.print("\n[green bold]✓ Attack library example complete.[/green bold]\n")


if __name__ == "__main__":
    main()
