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
        "gap_status": "closed",
        "coverage_fn": lambda lib: {
            "harm_categories": {
                "benchmark": 11,
                "ziran": len(HarmCategory) if HarmCategory is not None else 0,
            },
            "multi_step_vectors": {
                "benchmark": 440,
                "ziran": len(
                    [v for v in lib.vectors if getattr(v, "harm_category", None) is not None]
                ),
            },
        },
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
        "gap_status": "open",
        "coverage_fn": lambda lib: {
            "indirect_injection_vectors": {
                "benchmark": 1054,
                "ziran": _count_vectors_by_category(lib, "indirect_injection"),
            },
        },
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
        "gap_status": "open",
        "coverage_fn": lambda lib: {
            "indirect_injection_vectors": {
                "benchmark": 629,
                "ziran": _count_vectors_by_category(lib, "indirect_injection"),
            },
            "utility_measurement": {"benchmark": "yes", "ziran": "no"},
        },
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
        "gap_status": "closed",
        "coverage_fn": lambda lib: {
            "attack_tactics": {
                "benchmark": 18,
                "ziran": len(set(v.tactic or "single" for v in lib.vectors)) - 1,
            },
            "jailbreak_vectors": {
                "benchmark": 510,
                "ziran": _count_vectors_by_category(lib, "prompt_injection"),
            },
        },
    },
    {
        "name": "JailbreakBench",
        "venue": "NeurIPS 2024",
        "url": "https://arxiv.org/abs/2404.01318",
        "focus": "Standardized jailbreak evaluation",
        "test_cases": 100,
        "key_dimensions": ["100 behaviors", "standardized pipeline"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "partial",
        "coverage_fn": lambda lib: {
            "prompt_injection_vectors": {
                "benchmark": 100,
                "ziran": _count_vectors_by_category(lib, "prompt_injection"),
            },
        },
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
        "gap_status": "open",
        "coverage_fn": lambda _lib: {
            "quality_scoring": {"benchmark": "yes", "ziran": "no (binary detection)"},
        },
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
        "gap_status": "open",
        "coverage_fn": lambda lib: {
            "mcp_vectors": {"benchmark": 1312, "ziran": _count_vectors_by_tag(lib, "mcp")},
            "tool_poisoning": {"benchmark": "yes", "ziran": "no"},
        },
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
        "gap_status": "open",
        "coverage_fn": lambda lib: {
            "attack_categories": {
                "benchmark": 10,
                "ziran": len(set(v.category.value for v in lib.vectors)),
            },
            "total_vectors": {"benchmark": 400, "ziran": len(lib.vectors)},
        },
    },
    {
        "name": "TensorTrust",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2311.01011",
        "focus": "Human-generated prompt injection attacks",
        "test_cases": 126000,
        "key_dimensions": ["126K+ attacks", "human-generated"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "minimal",
        "coverage_fn": lambda lib: {
            "prompt_injection_vectors": {
                "benchmark": 126000,
                "ziran": _count_vectors_by_category(lib, "prompt_injection"),
            },
        },
    },
    {
        "name": "WildJailbreak",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2406.18510",
        "focus": "Real-world jailbreak tactic diversity",
        "test_cases": 105000,
        "key_dimensions": ["105K tactics", "real-world sourced"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "minimal",
        "coverage_fn": lambda lib: {
            "tactic_count": {
                "benchmark": 105000,
                "ziran": len(set(v.tactic or "single" for v in lib.vectors)),
            },
        },
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
        "gap_status": "open",
        "coverage_fn": lambda _lib: {
            "rag_vectors": {"benchmark": "yes", "ziran": "no"},
            "defense_evasion": {"benchmark": "yes", "ziran": "no"},
        },
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
        "gap_status": "closed",
        "coverage_fn": lambda _lib: {
            "business_impact_types": {"benchmark": 8, "ziran": 7},
        },
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
        "gap_status": "open",
        "coverage_fn": lambda lib: {
            "indirect_injection_vectors": {
                "benchmark": "multi-domain",
                "ziran": _count_vectors_by_category(lib, "indirect_injection"),
            },
        },
    },
    {
        "name": "CyberSecEval",
        "venue": "Meta, 2024",
        "url": None,
        "focus": "Cybersecurity-focused LLM evaluation",
        "test_cases": None,
        "key_dimensions": ["code generation safety", "cybersecurity knowledge"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "partial",
        "coverage_fn": lambda lib: {
            "total_vectors": {"benchmark": "multi-category", "ziran": len(lib.vectors)},
        },
    },
    {
        "name": "ToolEmu",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2309.15817",
        "focus": "LM-emulated tool sandbox evaluation",
        "test_cases": 144,
        "key_dimensions": ["144 cases", "emulated sandbox"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "partial",
        "coverage_fn": lambda lib: {
            "tool_manipulation_vectors": {
                "benchmark": 144,
                "ziran": _count_vectors_by_category(lib, "tool_manipulation"),
            },
        },
    },
    {
        "name": "R-Judge",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2407.01689",
        "focus": "Risk identification in agent interactions",
        "test_cases": 569,
        "key_dimensions": ["569 interaction records", "risk scoring"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "partial",
        "coverage_fn": lambda lib: {
            "detection_pipeline": {"benchmark": "risk scoring", "ziran": "5 detectors"},
        },
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
        "gap_status": "open",
        "coverage_fn": lambda _lib: {
            "resilience_gap": {"benchmark": "yes", "ziran": "no"},
        },
    },
    {
        "name": "ALERT",
        "venue": "2024",
        "url": "https://arxiv.org/abs/2404.08311",
        "focus": "Fine-grained risk taxonomy",
        "test_cases": 45000,
        "key_dimensions": ["45K+ prompts", "fine-grained categories"],
        "gap_id": None,
        "gap_issue": None,
        "gap_status": "partial",
        "coverage_fn": lambda lib: {
            "harm_categories": {
                "benchmark": "fine-grained",
                "ziran": len(HarmCategory) if HarmCategory is not None else 0,
            },
        },
    },
]


def collect_benchmark_comparison() -> dict:
    """Run coverage comparison against all benchmarks."""
    library = AttackLibrary()

    results = []
    for bench in BENCHMARKS:
        coverage = bench["coverage_fn"](library)
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
                "gap_status": bench["gap_status"],
                "coverage": coverage,
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


def print_summary(data: dict) -> None:
    """Print human-readable benchmark comparison."""
    print("Benchmark Coverage Comparison")
    print(f"{'=' * 60}")
    print(f"Benchmarks analyzed: {data['total_benchmarks']}")
    print(f"Status: {data['status_summary']}")
    print()

    print(f"{'Benchmark':<25} {'Cases':>8} {'Status':<10} {'Gap':<8}")
    print(f"{'-' * 25} {'-' * 8} {'-' * 10} {'-' * 8}")
    for b in data["benchmarks"]:
        cases = str(b["test_cases"]) if b["test_cases"] else "—"
        gap = b["gap_id"] or "—"
        print(f"{b['name']:<25} {cases:>8} {b['gap_status']:<10} {gap:<8}")

    print()
    print("Coverage details:")
    for b in data["benchmarks"]:
        print(f"\n  {b['name']} ({b['venue']}):")
        print(f"    Focus: {b['focus']}")
        for dim, vals in b["coverage"].items():
            if isinstance(vals, dict):
                bench_val = vals.get("benchmark", "?")
                ziran_val = vals.get("ziran", "?")
                print(f"    {dim}: benchmark={bench_val}, ziran={ziran_val}")
            else:
                print(f"    {dim}: {vals}")


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
