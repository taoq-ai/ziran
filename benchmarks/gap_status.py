"""Track gap analysis status from the ZIRAN benchmark gap analysis.

Usage:
    uv run python benchmarks/gap_status.py
    uv run python benchmarks/gap_status.py --json results/gap_status.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# Gap analysis data — manually maintained to match docs/reference/benchmarks/gap-analysis.md
GAPS = [
    {
        "id": "GAP-01",
        "title": "Benchmark harness",
        "priority": "critical",
        "issue": "#32",
        "status": "open",
        "benchmarks": ["All"],
        "effort": "large",
    },
    {
        "id": "GAP-02",
        "title": "Indirect prompt injection scale",
        "priority": "critical",
        "issue": "#33",
        "status": "open",
        "benchmarks": ["AgentDojo", "InjecAgent", "BIPIA"],
        "effort": "medium",
    },
    {
        "id": "GAP-03",
        "title": "MCP tool poisoning",
        "priority": "critical",
        "issue": "#34",
        "status": "open",
        "benchmarks": ["MCPTox"],
        "effort": "medium",
    },
    {
        "id": "GAP-04",
        "title": "Quality-aware jailbreak scoring",
        "priority": "critical",
        "issue": "#35",
        "status": "closed",
        "benchmarks": ["StrongREJECT", "HarmBench", "JailbreakBench"],
        "effort": "small",
    },
    {
        "id": "GAP-05",
        "title": "Utility-under-attack measurement",
        "priority": "important",
        "issue": "#36",
        "status": "open",
        "benchmarks": ["AgentDojo", "ASB"],
        "effort": "medium",
    },
    {
        "id": "GAP-06",
        "title": "Harmful multi-step task testing",
        "priority": "important",
        "issue": "#37",
        "status": "closed",
        "benchmarks": ["AgentHarm"],
        "effort": "medium",
    },
    {
        "id": "GAP-07",
        "title": "Business impact categorization",
        "priority": "important",
        "issue": "#38",
        "status": "open",
        "benchmarks": ["Agent-SafetyBench"],
        "effort": "small",
    },
    {
        "id": "GAP-08",
        "title": "Jailbreak tactic breadth",
        "priority": "important",
        "issue": "#39",
        "status": "closed",
        "benchmarks": ["HarmBench", "WildJailbreak", "TensorTrust"],
        "effort": "medium",
    },
    {
        "id": "GAP-09",
        "title": "Resilience gap metric",
        "priority": "important",
        "issue": "#40",
        "status": "open",
        "benchmarks": ["AILuminate"],
        "effort": "small",
    },
    {
        "id": "GAP-10",
        "title": "OWASP LLM04 (Model DoS)",
        "priority": "lower",
        "issue": "#41",
        "status": "closed",
        "benchmarks": ["OWASP completeness"],
        "effort": "small",
    },
    {
        "id": "GAP-11",
        "title": "OWASP LLM05 (Supply Chain)",
        "priority": "lower",
        "issue": "#42",
        "status": "open",
        "benchmarks": ["OWASP completeness"],
        "effort": "medium",
    },
    {
        "id": "GAP-12",
        "title": "OWASP LLM10 (Model Theft)",
        "priority": "lower",
        "issue": "#43",
        "status": "open",
        "benchmarks": ["OWASP completeness"],
        "effort": "small",
    },
    {
        "id": "GAP-13",
        "title": "RAG-specific poisoning",
        "priority": "lower",
        "issue": "#44",
        "status": "open",
        "benchmarks": ["LLMail-Inject"],
        "effort": "medium",
    },
    {
        "id": "GAP-14",
        "title": "Defense evasion measurement",
        "priority": "lower",
        "issue": "#45",
        "status": "open",
        "benchmarks": ["LLMail-Inject", "PINT"],
        "effort": "large",
    },
    {
        "id": "GAP-15",
        "title": "JailbreakBench coverage",
        "priority": "lower",
        "issue": "#54",
        "status": "closed",
        "benchmarks": ["JailbreakBench"],
        "effort": "medium",
    },
    {
        "id": "GAP-16",
        "title": "TensorTrust coverage",
        "priority": "lower",
        "issue": "#55",
        "status": "open",
        "benchmarks": ["TensorTrust"],
        "effort": "large",
    },
    {
        "id": "GAP-17",
        "title": "WildJailbreak coverage",
        "priority": "lower",
        "issue": "#56",
        "status": "open",
        "benchmarks": ["WildJailbreak"],
        "effort": "large",
    },
    {
        "id": "GAP-18",
        "title": "CyberSecEval coverage",
        "priority": "lower",
        "issue": "#57",
        "status": "open",
        "benchmarks": ["CyberSecEval"],
        "effort": "medium",
    },
    {
        "id": "GAP-19",
        "title": "ToolEmu coverage",
        "priority": "lower",
        "issue": "#58",
        "status": "open",
        "benchmarks": ["ToolEmu"],
        "effort": "medium",
    },
    {
        "id": "GAP-20",
        "title": "R-Judge coverage",
        "priority": "lower",
        "issue": "#59",
        "status": "closed",
        "benchmarks": ["R-Judge"],
        "effort": "medium",
    },
    {
        "id": "GAP-21",
        "title": "ALERT coverage",
        "priority": "lower",
        "issue": "#60",
        "status": "closed",
        "benchmarks": ["ALERT"],
        "effort": "large",
    },
    {
        "id": "GAP-22",
        "title": "MITRE ATLAS technique mapping",
        "priority": "important",
        "issue": "#61",
        "status": "open",
        "benchmarks": ["MITRE ATLAS"],
        "effort": "medium",
    },
    {
        "id": "GAP-23",
        "title": "AgentHarm multi-step vector scale",
        "priority": "important",
        "issue": "#131",
        "status": "open",
        "benchmarks": ["AgentHarm"],
        "effort": "large",
    },
]


def collect_gap_status() -> dict:
    """Collect gap analysis status."""
    status_counts: Counter[str] = Counter()
    priority_counts: Counter[str] = Counter()

    for gap in GAPS:
        status_counts[gap["status"]] += 1
        priority_counts[gap["priority"]] += 1

    return {
        "gaps": GAPS,
        "summary": {
            "total": len(GAPS),
            "by_status": dict(sorted(status_counts.items())),
            "by_priority": dict(sorted(priority_counts.items())),
            "closure_pct": round(status_counts.get("closed", 0) / len(GAPS) * 100, 1),
        },
    }


def print_summary(data: dict) -> None:
    """Print human-readable gap status."""
    summary = data["summary"]
    print("Gap Analysis Status")
    print(f"{'=' * 60}")
    print(f"Total gaps: {summary['total']}")
    print(f"Closure rate: {summary['closure_pct']}%")
    print(f"By status: {summary['by_status']}")
    print(f"By priority: {summary['by_priority']}")
    print()

    print(f"{'ID':<8} {'Title':<38} {'Priority':<10} {'Issue':<6} {'Status':<8}")
    print(f"{'-' * 8} {'-' * 38} {'-' * 10} {'-' * 6} {'-' * 8}")
    for gap in data["gaps"]:
        marker = "[x]" if gap["status"] == "closed" else "[ ]"
        print(
            f"{gap['id']:<8} {gap['title']:<38} {gap['priority']:<10} "
            f"{gap['issue']:<6} {marker} {gap['status']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Gap analysis status")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    args = parser.parse_args()

    data = collect_gap_status()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
