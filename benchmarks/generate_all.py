"""Orchestrate all benchmark scripts and generate the coverage comparison report.

Usage:
    uv run python benchmarks/generate_all.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.benchmark_comparison import collect_benchmark_comparison
from benchmarks.gap_status import collect_gap_status
from benchmarks.inventory import collect_inventory
from benchmarks.owasp_coverage import collect_owasp_coverage

RESULTS_DIR = Path(__file__).parent / "results"
DOCS_DIR = Path(__file__).parent.parent / "docs" / "reference" / "benchmarks"


def write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


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

    # ── Executive Summary ─────────────────────────────────────────
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

    # ── OWASP Coverage ────────────────────────────────────────────
    lines.append("## OWASP LLM Top 10 Coverage")
    lines.append("")
    lines.append("| Code | Category | Vectors | Status |")
    lines.append("|------|----------|---------|--------|")
    for cat_key, info in owasp["per_category"].items():
        status_icon = {
            "comprehensive": ":white_check_mark: Comprehensive",
            "strong": ":white_check_mark: Strong",
            "moderate": ":large_orange_diamond: Moderate",
            "planned": ":construction: Planned",
        }.get(info["status"], info["status"])
        vecs = str(info["vectors"]) if info["vectors"] > 0 else "—"
        lines.append(f"| **{cat_key}** | {info['name']} | {vecs} | {status_icon} |")
    lines.append("")
    if owasp["not_covered"]:
        lines.append(f"**Not covered:** {', '.join(owasp['not_covered'])}")
        lines.append("")

    # ── Benchmark Comparison ──────────────────────────────────────
    lines.append("## Benchmark Comparison")
    lines.append("")
    lines.append("| Benchmark | Venue | Focus | Test Cases | ZIRAN Status | Gap |")
    lines.append("|-----------|-------|-------|------------|-------------|-----|")
    for b in benchmarks["benchmarks"]:
        cases = f"{b['test_cases']:,}" if b["test_cases"] else "—"
        gap_link = f"[{b['gap_id']}]({b['gap_issue']})" if b["gap_id"] else "—"
        status_icon = {
            "closed": ":white_check_mark:",
            "open": ":construction:",
            "partial": ":large_orange_diamond:",
            "minimal": ":red_circle:",
        }.get(b["gap_status"], "")
        lines.append(
            f"| **{b['name']}** | {b['venue']} | {b['focus']} | "
            f"{cases} | {status_icon} {b['gap_status']} | {gap_link} |"
        )
    lines.append("")

    # ── Gap Status ────────────────────────────────────────────────
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

    # ── Vector Inventory ──────────────────────────────────────────
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

    print("Generating markdown report...")
    md = generate_markdown(inventory, owasp, benchmarks, gaps)
    report_path = DOCS_DIR / "coverage-comparison.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(md)

    print(f"\nResults written to {RESULTS_DIR}/")
    print(f"Report written to {report_path}")
    print("\nSummary:")
    print(f"  Vectors: {inventory['total_vectors']}")
    print(f"  OWASP coverage: {owasp['coverage_pct']}%")
    print(f"  Benchmarks: {benchmarks['total_benchmarks']}")
    print(
        f"  Gaps closed: {gaps['summary']['by_status'].get('closed', 0)}/{gaps['summary']['total']}"
    )


if __name__ == "__main__":
    main()
