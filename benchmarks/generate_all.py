"""Orchestrate all benchmark scripts and generate the coverage comparison report.

Usage:
    uv run python benchmarks/generate_all.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.accuracy_metrics import collect_accuracy_metrics
from benchmarks.benchmark_comparison import collect_benchmark_comparison
from benchmarks.gap_status import collect_gap_status
from benchmarks.inventory import collect_inventory
from benchmarks.owasp_coverage import collect_owasp_coverage
from benchmarks.performance_metrics import collect_performance_metrics
from benchmarks.utility_metrics import collect_utility_metrics

RESULTS_DIR = Path(__file__).parent / "results"
DOCS_DIR = Path(__file__).parent.parent / "docs" / "reference" / "benchmarks"
README_PATH = Path(__file__).parent / "README.md"


def write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _progress_bar_md(pct: float, width: int = 15) -> str:
    """Render a Unicode progress bar for markdown."""
    filled = round(pct / 100 * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def _status_icon(status: str) -> str:
    return {
        "closed": ":white_check_mark:",
        "open": ":construction:",
        "partial": ":large_orange_diamond:",
        "minimal": ":red_circle:",
    }.get(status, "")


def generate_markdown(
    inventory: dict,
    owasp: dict,
    benchmarks: dict,
    gaps: dict,
) -> str:
    """Generate the coverage comparison markdown report."""
    lines: list[str] = []

    lines.append("# Benchmark Coverage Comparison")
    lines.append("")
    lines.append(
        "Auto-generated comparison of ZIRAN's attack vector library against "
        "published AI agent security benchmarks."
    )
    lines.append("")
    ts = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    lines.append(f"*Last updated: {ts}*")
    lines.append("")

    # -- Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"- **{inventory['total_vectors']}** attack vectors across "
        f"**{len(inventory['categories'])}** attack categories"
    )
    lines.append(
        f"- **{owasp['coverage_pct']}%** OWASP LLM Top 10 coverage "
        f"({len(owasp['covered'])}/{owasp['owasp_categories_total']} categories)"
    )
    n_tactics = len(inventory["tactics"]) - (1 if "single" in inventory["tactics"] else 0)
    lines.append(
        f"- **{n_tactics}** multi-turn jailbreak tactics, "
        f"**{inventory['encoding_types']}** encoding types"
    )
    lines.append(f"- **{inventory['multi_turn_vectors']}** multi-turn vectors")
    lines.append(f"- **{inventory['harm_category_count']}** harm categories (AgentHarm-aligned)")
    gap_summary = gaps["summary"]
    lines.append(
        f"- Gap closure: **{gap_summary['closure_pct']}%** "
        f"({gap_summary['by_status'].get('closed', 0)}/{gap_summary['total']} gaps closed)"
    )
    lines.append("")

    # -- OWASP Coverage
    lines.append("## OWASP LLM Top 10 Coverage")
    lines.append("")
    lines.append("| Code | Category | Vectors | Status |")
    lines.append("|------|----------|---------|--------|")
    for cat_key, info in owasp["per_category"].items():
        status_label = {
            "comprehensive": ":white_check_mark: Comprehensive",
            "strong": ":white_check_mark: Strong",
            "moderate": ":large_orange_diamond: Moderate",
            "planned": ":construction: Planned",
        }.get(info["status"], info["status"])
        vecs = str(info["vectors"]) if info["vectors"] > 0 else "\u2014"
        lines.append(f"| **{cat_key}** | {info['name']} | {vecs} | {status_label} |")
    lines.append("")
    if owasp["not_covered"]:
        lines.append(f"**Not covered:** {', '.join(owasp['not_covered'])}")
        lines.append("")

    # -- Benchmark Comparison (with progress bars)
    lines.append("## Benchmark Comparison")
    lines.append("")
    lines.append("| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |")
    lines.append("|-----------|-------|-----------|-------:|------:|----------|--------|-----|")
    for b in benchmarks["benchmarks"]:
        gap_link = f"[{b['gap_id']}]({b['gap_issue']})" if b["gap_id"] else "\u2014"
        icon = _status_icon(b["gap_status"])
        first_row = True
        for m in b["metrics"]:
            name_col = f"**{b['name']}**" if first_row else ""
            venue_col = b["venue"] if first_row else ""
            status_col = f"{icon} {b['gap_status']}" if first_row else ""
            gap_col = gap_link if first_row else ""

            target_str = f"{m['target']:,}" if m["target"] is not None else "\u2014"
            impl_str = str(m["implemented"])

            if m["pct"] is not None:
                bar = f"`{_progress_bar_md(m['pct'])}` {m['pct']}%"
            else:
                note = m.get("note", "N/A")
                bar = f"_{note}_" if note else "\u2014"

            lines.append(
                f"| {name_col} | {venue_col} | {m['dimension']} | "
                f"{target_str} | {impl_str} | {bar} | {status_col} | {gap_col} |"
            )
            first_row = False
    lines.append("")

    # -- Gap Status
    lines.append("## Gap Status Dashboard")
    lines.append("")
    lines.append("See [Gap Analysis](gap-analysis.md) for full details.")
    lines.append("")
    lines.append("| ID | Gap | Priority | Issue | Status |")
    lines.append("|----|-----|----------|-------|--------|")
    for gap in gaps["gaps"]:
        check = ":white_check_mark:" if gap["status"] == "closed" else ":construction:"
        lines.append(
            f"| {gap['id']} | {gap['title']} | {gap['priority']} | "
            f"[{gap['issue']}](https://github.com/taoq-ai/ziran/issues/{gap['issue'].lstrip('#')}) | "
            f"{check} {gap['status']} |"
        )
    lines.append("")

    # -- Vector Inventory
    lines.append("## Vector Inventory")
    lines.append("")
    lines.append("### By Attack Category")
    lines.append("")
    lines.append("| Category | Vectors |")
    lines.append("|----------|---------|")
    for cat, count in sorted(inventory["categories"].items(), key=lambda x: -x[1]):
        lines.append(f"| {cat} | {count} |")
    lines.append("")

    lines.append("### By Tactic")
    lines.append("")
    lines.append("| Tactic | Vectors |")
    lines.append("|--------|---------|")
    for tactic, count in sorted(inventory["tactics"].items(), key=lambda x: -x[1]):
        lines.append(f"| {tactic} | {count} |")
    lines.append("")

    lines.append("### By Severity")
    lines.append("")
    lines.append("| Severity | Vectors |")
    lines.append("|----------|---------|")
    for sev, count in sorted(inventory["severities"].items()):
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    if inventory["harm_categories"]:
        lines.append("### By Harm Category")
        lines.append("")
        lines.append("| Harm Category | Vectors |")
        lines.append("|---------------|---------|")
        for cat, count in sorted(inventory["harm_categories"].items()):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by `benchmarks/generate_all.py` on {ts}.*")
    lines.append("")

    return "\n".join(lines)


def generate_readme(
    inventory: dict,
    owasp: dict,
    benchmarks: dict,
    gaps: dict,
) -> str:
    """Generate the benchmarks/README.md for GitHub visibility."""
    lines: list[str] = []

    lines.append("# ZIRAN Benchmark Coverage")
    lines.append("")
    lines.append(
        "How ZIRAN's attack vector library compares against published AI agent security benchmarks."
    )
    lines.append("")

    # -- Current State
    lines.append("## Current State")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Attack vectors | **{inventory['total_vectors']}** |")
    lines.append(f"| Attack categories | **{len(inventory['categories'])}** |")
    lines.append(
        f"| OWASP LLM Top 10 | **{owasp['coverage_pct']}%** "
        f"({len(owasp['covered'])}/{owasp['owasp_categories_total']}) |"
    )
    n_tactics = len(inventory["tactics"]) - (1 if "single" in inventory["tactics"] else 0)
    lines.append(f"| Multi-turn tactics | **{n_tactics}** |")
    lines.append(f"| Encoding types | **{inventory['encoding_types']}** |")
    lines.append(f"| Benchmarks analyzed | **{benchmarks['total_benchmarks']}** |")
    gap_summary = gaps["summary"]
    closed = gap_summary["by_status"].get("closed", 0)
    total = gap_summary["total"]
    lines.append(f"| Gap closure | **{gap_summary['closure_pct']}%** ({closed}/{total}) |")
    lines.append("")

    # -- OWASP Coverage
    lines.append("## OWASP LLM Top 10 Coverage")
    lines.append("")
    lines.append("| Code | Category | Vectors | Status |")
    lines.append("|------|----------|---------|--------|")
    for cat_key, info in owasp["per_category"].items():
        status_label = {
            "comprehensive": ":white_check_mark: Comprehensive",
            "strong": ":white_check_mark: Strong",
            "moderate": ":large_orange_diamond: Moderate",
            "planned": ":construction: Planned",
        }.get(info["status"], info["status"])
        vecs = str(info["vectors"]) if info["vectors"] > 0 else "\u2014"
        issue_note = ""
        if "issue" in info:
            issue_note = f" ([{info['issue']}](https://github.com/taoq-ai/ziran/issues/{info['issue'].lstrip('#')}))"
        lines.append(f"| **{cat_key}** | {info['name']} | {vecs} | {status_label}{issue_note} |")
    lines.append("")

    # -- Benchmark Comparison with progress bars
    lines.append("## Benchmark Comparison")
    lines.append("")
    lines.append("| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |")
    lines.append("|-----------|-------|-----------|-------:|------:|----------|--------|-----|")
    for b in benchmarks["benchmarks"]:
        gap_link = (
            f"[{b['gap_id']}](https://github.com/taoq-ai/ziran/issues/{b['gap_issue'].lstrip('#')})"
            if b["gap_id"]
            else "\u2014"
        )
        icon = _status_icon(b["gap_status"])
        first_row = True
        for m in b["metrics"]:
            name_col = f"**{b['name']}**" if first_row else ""
            venue_col = b["venue"] if first_row else ""
            status_col = f"{icon} {b['gap_status']}" if first_row else ""
            gap_col = gap_link if first_row else ""

            target_str = f"{m['target']:,}" if m["target"] is not None else "\u2014"
            impl_str = str(m["implemented"])

            if m["pct"] is not None:
                bar = f"`{_progress_bar_md(m['pct'])}` {m['pct']}%"
            else:
                note = m.get("note", "N/A")
                bar = f"_{note}_" if note else "\u2014"

            lines.append(
                f"| {name_col} | {venue_col} | {m['dimension']} | "
                f"{target_str} | {impl_str} | {bar} | {status_col} | {gap_col} |"
            )
            first_row = False
    lines.append("")

    # -- Gap Status
    lines.append("## Gap Status")
    lines.append("")
    lines.append("| ID | Gap | Priority | Status |")
    lines.append("|----|-----|----------|--------|")
    for gap in gaps["gaps"]:
        check = ":white_check_mark:" if gap["status"] == "closed" else ":construction:"
        lines.append(
            f"| {gap['id']} | {gap['title']} | {gap['priority']} | "
            f"{check} {gap['status']} "
            f"([{gap['issue']}](https://github.com/taoq-ai/ziran/issues/{gap['issue'].lstrip('#')})) |"
        )
    lines.append("")

    # -- Vector Inventory
    lines.append("## Vector Inventory")
    lines.append("")
    lines.append("### By Attack Category")
    lines.append("")
    lines.append("| Category | Vectors |")
    lines.append("|----------|---------|")
    for cat, count in sorted(inventory["categories"].items(), key=lambda x: -x[1]):
        lines.append(f"| {cat} | {count} |")
    lines.append("")

    lines.append("### By Tactic")
    lines.append("")
    lines.append("| Tactic | Vectors |")
    lines.append("|--------|---------|")
    for tactic, count in sorted(inventory["tactics"].items(), key=lambda x: -x[1]):
        lines.append(f"| {tactic} | {count} |")
    lines.append("")

    lines.append("### By Severity")
    lines.append("")
    lines.append("| Severity | Vectors |")
    lines.append("|----------|---------|")
    for sev, count in sorted(inventory["severities"].items()):
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    # -- Scripts
    lines.append("## Scripts")
    lines.append("")
    lines.append("Each script is independently runnable:")
    lines.append("")
    lines.append("```bash")
    lines.append("# Individual scripts")
    lines.append("uv run python benchmarks/inventory.py")
    lines.append("uv run python benchmarks/owasp_coverage.py")
    lines.append("uv run python benchmarks/benchmark_comparison.py")
    lines.append("uv run python benchmarks/gap_status.py")
    lines.append("")
    lines.append("# Generate all results + markdown report")
    lines.append("uv run python benchmarks/generate_all.py")
    lines.append("")
    lines.append("# Write JSON output")
    lines.append("uv run python benchmarks/inventory.py --json benchmarks/results/inventory.json")
    lines.append("```")
    lines.append("")

    # -- Regenerating
    lines.append("## Regenerating")
    lines.append("")
    lines.append("After adding new vectors or closing gaps, regenerate:")
    lines.append("")
    lines.append("```bash")
    lines.append("uv run python benchmarks/generate_all.py")
    lines.append("```")
    lines.append("")
    lines.append(
        "This updates `benchmarks/results/*.json`, `benchmarks/README.md`, "
        "and `docs/reference/benchmarks/coverage-comparison.md`."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    print("Collecting inventory...")
    inventory = collect_inventory()
    write_json(inventory, RESULTS_DIR / "inventory.json")

    print("Analyzing OWASP coverage...")
    owasp = collect_owasp_coverage()
    write_json(owasp, RESULTS_DIR / "owasp_coverage.json")

    print("Comparing against benchmarks...")
    benchmarks = collect_benchmark_comparison()
    write_json(benchmarks, RESULTS_DIR / "benchmark_comparison.json")

    print("Collecting gap status...")
    gaps = collect_gap_status()
    write_json(gaps, RESULTS_DIR / "gap_status.json")

    print("Computing accuracy metrics...")
    accuracy = collect_accuracy_metrics()
    write_json(accuracy, RESULTS_DIR / "accuracy_metrics.json")

    print("Running performance benchmarks...")
    performance = collect_performance_metrics()
    write_json(performance, RESULTS_DIR / "performance_metrics.json")

    print("Computing utility-under-attack metrics...")
    utility = collect_utility_metrics()
    write_json(utility, RESULTS_DIR / "utility_metrics.json")

    print("Generating markdown report...")
    md = generate_markdown(inventory, owasp, benchmarks, gaps)
    report_path = DOCS_DIR / "coverage-comparison.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(md)

    print("Generating README...")
    readme = generate_readme(inventory, owasp, benchmarks, gaps)
    README_PATH.write_text(readme)

    print(f"\nResults written to {RESULTS_DIR}/")
    print(f"Report written to {report_path}")
    print(f"README written to {README_PATH}")
    print("\nSummary:")
    print(f"  Vectors: {inventory['total_vectors']}")
    print(f"  OWASP coverage: {owasp['coverage_pct']}%")
    print(f"  Benchmarks: {benchmarks['total_benchmarks']}")
    print(
        f"  Gaps closed: {gaps['summary']['by_status'].get('closed', 0)}/{gaps['summary']['total']}"
    )


if __name__ == "__main__":
    main()
