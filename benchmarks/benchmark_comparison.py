"""Compare ZIRAN's coverage against published AI agent security benchmarks.

Usage:
    uv run python benchmarks/benchmark_comparison.py
    uv run python benchmarks/benchmark_comparison.py --json results/benchmark_comparison.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from benchmarks.gap_status import GAPS
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.attack import OwaspLlmCategory  # noqa: TC001

try:
    from ziran.domain.entities.attack import HarmCategory
except ImportError:
    HarmCategory = None  # type: ignore[assignment,misc]


def _count_vectors_by_tag(library: AttackLibrary, tag: str) -> int:
    return len(library.get_attacks_by_tag(tag))


def _count_vectors_by_category(library: AttackLibrary, category: str) -> int:
    return len(library.get_attacks_by_category(category))


def _count_owasp(library: AttackLibrary, cat: OwaspLlmCategory) -> int:
    return len(library.get_attacks_by_owasp(cat))


def _gap_status_lookup() -> dict[str, str]:
    """Build a gap_id → status lookup from the canonical gap_status data."""
    return {g["id"]: g["status"] for g in GAPS}


# ── Benchmark reference data ────────────────────────────────────────

BENCHMARKS = [
    {
        "name": "AgentHarm",
        "venue": "ICLR 2025",
        "url": "https://arxiv.org/abs/2410.09024",
        "focus": "Harmful multi-step task completion",
        "test_cases": 440,
        "key_dimensions": ["11 harm categories", "110+ behaviors", "104 tools"],
        "gap_id": "GAP-06",
        "gap_issue": "#37",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Harm categories",
                "target": 11,
                "implemented": len(HarmCategory) if HarmCategory is not None else 0,
            },
        ],
    },
    {
        "name": "AgentHarm",
        "venue": "ICLR 2025",
        "url": "https://arxiv.org/abs/2410.09024",
        "focus": "Multi-step harmful task scale",
        "test_cases": 440,
        "key_dimensions": ["440 multi-step scenarios"],
        "gap_id": "GAP-23",
        "gap_issue": "#131",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Multi-step vectors",
                "target": 440,
                "implemented": len(
                    [v for v in lib.vectors if getattr(v, "harm_category", None) is not None]
                ),
            },
        ],
    },
    {
        "name": "InjecAgent",
        "venue": "ACL 2024",
        "url": "https://arxiv.org/abs/2403.02691",
        "focus": "Indirect prompt injection via tool outputs",
        "test_cases": 1054,
        "key_dimensions": ["1,054 test cases", "62 attacker tools", "17 user tools"],
        "gap_id": "GAP-02",
        "gap_issue": "#33",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Indirect injection vectors",
                "target": 1054,
                "implemented": _count_vectors_by_category(lib, "indirect_injection"),
            },
        ],
    },
    {
        "name": "AgentDojo",
        "venue": "NeurIPS 2024",
        "url": "https://arxiv.org/abs/2406.13352",
        "focus": "Indirect injection + utility measurement",
        "test_cases": 629,
        "key_dimensions": ["629 injection cases", "97 tasks", "utility metrics"],
        "gap_id": "GAP-02",
        "gap_issue": "#33",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Indirect injection vectors",
                "target": 629,
                "implemented": _count_vectors_by_category(lib, "indirect_injection"),
            },
            {
                "dimension": "Utility measurement (baseline + post-attack)",
                "target": 1,
                "implemented": 1,
                "note": "UtilityMeasurer: baseline_score, post_attack_score, utility_delta",
            },
        ],
    },
    {
        "name": "HarmBench",
        "venue": "ICML 2024",
        "url": "https://arxiv.org/abs/2402.04249",
        "focus": "Jailbreak attack methods evaluation",
        "test_cases": 510,
        "key_dimensions": ["510 behaviors", "18 attack methods", "33 LLMs"],
        "gap_id": "GAP-08",
        "gap_issue": "#39",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Attack tactics",
                "target": 18,
                "implemented": len(set(v.tactic or "single" for v in lib.vectors)) - 1,
            },
            {
                "dimension": "Jailbreak vectors",
                "target": 510,
                "implemented": _count_vectors_by_category(lib, "prompt_injection"),
            },
        ],
    },
    {
        "name": "JailbreakBench",
        "venue": "NeurIPS 2024",
        "url": "https://arxiv.org/abs/2404.01318",
        "focus": "Standardized jailbreak evaluation",
        "test_cases": 100,
        "key_dimensions": ["100 behaviors", "standardized pipeline"],
        "gap_id": "GAP-15",
        "gap_issue": "#54",
        "coverage_fn": lambda lib: [
            {
                "dimension": "JBB categories (10)",
                "target": 10,
                "implemented": len(
                    {
                        t.split("jbb:", 1)[1]
                        for v in lib.vectors
                        for t in v.tags
                        if t.startswith("jbb:")
                    }
                ),
            },
            {
                "dimension": "Prompt injection vectors",
                "target": 100,
                "implemented": _count_vectors_by_category(lib, "prompt_injection"),
            },
        ],
    },
    {
        "name": "StrongREJECT",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2402.10260",
        "focus": "Quality-aware jailbreak scoring",
        "test_cases": None,
        "key_dimensions": ["composite scoring formula", "specificity + convincingness"],
        "gap_id": "GAP-04",
        "gap_issue": "#35",
        "coverage_fn": lambda _lib: [
            {
                "dimension": "StrongREJECT composite formula",
                "target": 1,
                "implemented": 1,
                "note": "QualityScore: (1 - refusal) * (specificity + convincingness) / 2",
            },
            {
                "dimension": "Scoring dimensions (refusal, specificity, convincingness)",
                "target": 3,
                "implemented": 3,
            },
        ],
    },
    {
        "name": "MCPTox",
        "venue": "2025",
        "url": None,
        "focus": "MCP tool poisoning detection",
        "test_cases": 1312,
        "key_dimensions": ["1,312 malicious cases", "353 real MCP tools"],
        "gap_id": "GAP-03",
        "gap_issue": "#34",
        "coverage_fn": lambda lib: [
            {
                "dimension": "MCP vectors",
                "target": 1312,
                "implemented": _count_vectors_by_tag(lib, "mcp"),
            },
        ],
    },
    {
        "name": "Agent Security Bench (ASB)",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2410.02644",
        "focus": "Multi-scenario agent security",
        "test_cases": 400,
        "key_dimensions": ["10 scenarios", "400+ tools", "7 metrics"],
        "gap_id": "GAP-01",
        "gap_issue": "#32",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Attack categories",
                "target": 10,
                "implemented": len(set(v.category.value for v in lib.vectors)),
            },
            {
                "dimension": "Total vectors",
                "target": 400,
                "implemented": len(lib.vectors),
            },
            {
                "dimension": "Utility-under-attack measurement",
                "target": 1,
                "implemented": 1,
                "note": "Pre/post-attack utility scoring with per-task breakdown",
            },
        ],
    },
    {
        "name": "TensorTrust",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2311.01011",
        "focus": "Human-generated prompt injection attacks",
        "test_cases": 126000,
        "key_dimensions": ["126K+ attacks", "human-generated"],
        "gap_id": "GAP-16",
        "gap_issue": "#55",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Prompt injection vectors",
                "target": 126000,
                "implemented": _count_vectors_by_category(lib, "prompt_injection"),
            },
        ],
    },
    {
        "name": "WildJailbreak",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2406.18510",
        "focus": "Real-world jailbreak tactic diversity",
        "test_cases": 105000,
        "key_dimensions": ["105K tactics", "real-world sourced"],
        "gap_id": "GAP-17",
        "gap_issue": "#56",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Jailbreak tactics",
                "target": 105000,
                "implemented": len(set(v.tactic or "single" for v in lib.vectors)),
            },
        ],
    },
    {
        "name": "LLMail-Inject",
        "venue": "2024",
        "url": None,
        "focus": "RAG injection + defense evasion",
        "test_cases": None,
        "key_dimensions": ["RAG-specific", "defense evasion testing"],
        "gap_id": "GAP-13",
        "gap_issue": "#44",
        "coverage_fn": lambda _lib: [
            {
                "dimension": "RAG injection vectors",
                "target": None,
                "implemented": 0,
                "note": "Not yet implemented",
            },
        ],
    },
    {
        "name": "Agent-SafetyBench",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2410.10862",
        "focus": "Business impact categorization",
        "test_cases": 2000,
        "key_dimensions": ["2K cases", "8 risk categories"],
        "gap_id": "GAP-07",
        "gap_issue": "#38",
        "coverage_fn": lambda _lib: [
            {
                "dimension": "Business impact types",
                "target": 8,
                "implemented": 7,
            },
        ],
    },
    {
        "name": "BIPIA",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2312.14197",
        "focus": "Indirect injection in applications",
        "test_cases": None,
        "key_dimensions": ["multi-domain", "application-level injection"],
        "gap_id": "GAP-02",
        "gap_issue": "#33",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Indirect injection vectors",
                "target": None,
                "implemented": _count_vectors_by_category(lib, "indirect_injection"),
                "note": "Multi-domain benchmark — no fixed target count",
            },
        ],
    },
    {
        "name": "CyberSecEval",
        "venue": "Meta, 2024",
        "url": None,
        "focus": "Cybersecurity-focused LLM evaluation",
        "test_cases": None,
        "key_dimensions": ["code generation safety", "cybersecurity knowledge"],
        "gap_id": "GAP-18",
        "gap_issue": "#57",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Total vectors",
                "target": None,
                "implemented": len(lib.vectors),
                "note": "Multi-category benchmark — partial overlap",
            },
        ],
    },
    {
        "name": "ToolEmu",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2309.15817",
        "focus": "LM-emulated tool sandbox evaluation",
        "test_cases": 144,
        "key_dimensions": ["144 cases", "emulated sandbox"],
        "gap_id": "GAP-19",
        "gap_issue": "#58",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Tool manipulation vectors",
                "target": 144,
                "implemented": _count_vectors_by_category(lib, "tool_manipulation"),
            },
        ],
    },
    {
        "name": "R-Judge",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2407.01689",
        "focus": "Risk identification in agent interactions",
        "test_cases": 569,
        "key_dimensions": ["569 interaction records", "risk scoring"],
        "gap_id": "GAP-20",
        "gap_issue": "#59",
        "coverage_fn": lambda lib: [
            {
                "dimension": "R-Judge risk types (10)",
                "target": 10,
                "implemented": len(
                    {
                        t.split("rjudge:", 1)[1]
                        for v in lib.vectors
                        for t in v.tags
                        if t.startswith("rjudge:")
                    }
                ),
            },
            {
                "dimension": "Risk scoring detectors",
                "target": None,
                "implemented": 5,
                "note": "5 detectors — different approach than interaction records",
            },
        ],
    },
    {
        "name": "AILuminate",
        "venue": "MLCommons, 2025",
        "url": None,
        "focus": "Resilience gap measurement",
        "test_cases": None,
        "key_dimensions": ["baseline vs attack delta", "resilience gap metric"],
        "gap_id": "GAP-09",
        "gap_issue": "#40",
        "coverage_fn": lambda _lib: [
            {
                "dimension": "Resilience gap metric",
                "target": 1,
                "implemented": 1,
                "note": "baseline_performance - under_attack_performance delta",
            },
            {
                "dimension": "Baseline performance measurement",
                "target": 1,
                "implemented": 1,
            },
            {
                "dimension": "Under-attack performance measurement",
                "target": 1,
                "implemented": 1,
            },
        ],
    },
    {
        "name": "ALERT",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2404.08676",
        "focus": "Fine-grained risk taxonomy",
        "test_cases": 45000,
        "key_dimensions": ["45K+ prompts", "6 macro / 32 micro categories"],
        "gap_id": "GAP-21",
        "gap_issue": "#60",
        "coverage_fn": lambda lib: [
            {
                "dimension": "ALERT micro categories (32)",
                "target": 32,
                "implemented": len(
                    {
                        t.split("alert:", 1)[1]
                        for v in lib.vectors
                        for t in v.tags
                        if t.startswith("alert:")
                    }
                ),
            },
            {
                "dimension": "Harm categories",
                "target": None,
                "implemented": len(HarmCategory) if HarmCategory is not None else 0,
            },
        ],
    },
    {
        "name": "MITRE ATLAS",
        "venue": "MITRE, 2025",
        "url": "https://atlas.mitre.org/",
        "focus": "Adversarial ML threat taxonomy (TTPs)",
        "test_cases": None,
        "key_dimensions": ["15 tactics", "66 techniques", "14 AI agent techniques"],
        "gap_id": "GAP-22",
        "gap_issue": "#61",
        "coverage_fn": lambda lib: [
            {
                "dimension": "Attack categories vs tactics",
                "target": 15,
                "implemented": len(set(v.category.value for v in lib.vectors)),
            },
            {
                "dimension": "ATLAS technique mapping",
                "target": None,
                "implemented": 0,
                "note": "No atlas_mapping field yet — mapping planned",
            },
        ],
    },
]


def _compute_status(metrics: list[dict]) -> str:
    """Derive a status from coverage metrics."""
    has_numeric = False
    total_pct = 0.0
    n_metrics = 0

    for m in metrics:
        if m["target"] is not None and m["target"] > 0:
            has_numeric = True
            pct = min(m["implemented"] / m["target"] * 100, 100)
            total_pct += pct
            n_metrics += 1

    if not has_numeric:
        # All qualitative — check if any are implemented
        any_impl = any(m["implemented"] > 0 for m in metrics)
        return "partial" if any_impl else "open"

    avg_pct = total_pct / n_metrics if n_metrics > 0 else 0
    if avg_pct >= 80:
        return "closed"
    if avg_pct >= 20:
        return "partial"
    if avg_pct > 0:
        return "minimal"
    return "open"


def collect_benchmark_comparison() -> dict:
    """Run coverage comparison against all benchmarks."""
    library = AttackLibrary()
    gap_lookup = _gap_status_lookup()

    results = []
    for bench in BENCHMARKS:
        metrics = bench["coverage_fn"](library)

        # Compute per-metric percentages
        for m in metrics:
            if m["target"] is not None and m["target"] > 0:
                m["pct"] = round(min(m["implemented"] / m["target"] * 100, 100), 1)
            else:
                m["pct"] = None

        # Derive gap_status from canonical source if gap exists
        gap_id = bench["gap_id"]
        if gap_id and gap_id in gap_lookup:
            gap_status = gap_lookup[gap_id]
        else:
            gap_status = _compute_status(metrics)

        results.append(
            {
                "name": bench["name"],
                "venue": bench["venue"],
                "url": bench["url"],
                "focus": bench["focus"],
                "test_cases": bench["test_cases"],
                "key_dimensions": bench["key_dimensions"],
                "gap_id": bench["gap_id"],
                "gap_issue": bench["gap_issue"],
                "gap_status": gap_status,
                "metrics": metrics,
            }
        )

    status_counts: Counter[str] = Counter()
    for r in results:
        status_counts[r["gap_status"]] += 1

    return {
        "total_benchmarks": len(results),
        "status_summary": dict(sorted(status_counts.items())),
        "benchmarks": results,
    }


def _progress_bar(pct: float, width: int = 15) -> str:
    """Render a text progress bar."""
    filled = round(pct / 100 * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def print_summary(data: dict) -> None:
    """Print human-readable benchmark comparison."""
    print("Benchmark Coverage Comparison")
    print(f"{'=' * 80}")
    print(f"Benchmarks analyzed: {data['total_benchmarks']}")
    print(f"Status: {data['status_summary']}")
    print()

    for b in data["benchmarks"]:
        gap = b["gap_id"] or "\u2014"
        status = b["gap_status"]
        print(f"\n  {b['name']} ({b['venue']}) [{status}] {gap}")
        print(f"    Focus: {b['focus']}")
        for m in b["metrics"]:
            target = m["target"]
            impl = m["implemented"]
            if m["pct"] is not None:
                bar = _progress_bar(m["pct"])
                print(f"    {m['dimension']}: {impl}/{target} {bar} {m['pct']}%")
            else:
                note = m.get("note", "")
                print(f"    {m['dimension']}: {impl} {note}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark coverage comparison")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    args = parser.parse_args()

    data = collect_benchmark_comparison()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
