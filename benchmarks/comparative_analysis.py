"""Comparative analysis of ZIRAN against other AI security testing tools.

Produces a feature comparison matrix documenting capabilities across ZIRAN,
Promptfoo, Garak, Inspect AI, and PyRIT based on published documentation.

Usage:
    uv run python benchmarks/comparative_analysis.py
    uv run python benchmarks/comparative_analysis.py --json results/comparative.json
    uv run python benchmarks/comparative_analysis.py --markdown
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ziran.application.attacks.library import get_attack_library

# Tool capability matrix based on published documentation and features.
# Each tool has capabilities scored as:
#   "full" = comprehensive support
#   "partial" = limited or basic support
#   "none" = not supported
#   "planned" = on roadmap / in development

TOOLS: list[dict] = [
    {
        "name": "ZIRAN",
        "url": "https://github.com/taoq-ai/ziran",
        "category": "Agent Security Scanner",
        "license": "Apache-2.0",
    },
    {
        "name": "Promptfoo",
        "url": "https://github.com/promptfoo/promptfoo",
        "category": "LLM Testing Framework",
        "license": "MIT",
    },
    {
        "name": "Garak",
        "url": "https://github.com/NVIDIA/garak",
        "category": "LLM Vulnerability Scanner",
        "license": "Apache-2.0",
    },
    {
        "name": "Inspect AI",
        "url": "https://github.com/UKGovernmentBEIS/inspect_ai",
        "category": "AI Safety Evaluation",
        "license": "MIT",
    },
    {
        "name": "PyRIT",
        "url": "https://github.com/Azure/PyRIT",
        "category": "AI Red Teaming",
        "license": "MIT",
    },
]

CAPABILITY_MATRIX: dict[str, dict[str, str]] = {
    "Prompt injection detection": {
        "ZIRAN": "full",
        "Promptfoo": "full",
        "Garak": "full",
        "Inspect AI": "partial",
        "PyRIT": "full",
    },
    "Indirect injection vectors": {
        "ZIRAN": "full",
        "Promptfoo": "partial",
        "Garak": "full",
        "Inspect AI": "partial",
        "PyRIT": "partial",
    },
    "Multi-turn jailbreak tactics": {
        "ZIRAN": "full",
        "Promptfoo": "partial",
        "Garak": "full",
        "Inspect AI": "none",
        "PyRIT": "full",
    },
    "Tool chain discovery": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "Side-effect detection": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "MCP/A2A protocol support": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "Multi-phase campaign": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "partial",
        "Inspect AI": "partial",
        "PyRIT": "partial",
    },
    "Knowledge graph analysis": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "OWASP LLM Top 10 mapping": {
        "ZIRAN": "full",
        "Promptfoo": "full",
        "Garak": "partial",
        "Inspect AI": "none",
        "PyRIT": "partial",
    },
    "Encoding/obfuscation attacks": {
        "ZIRAN": "partial",
        "Promptfoo": "full",
        "Garak": "full",
        "Inspect AI": "none",
        "PyRIT": "full",
    },
    "Custom attack definitions": {
        "ZIRAN": "full",
        "Promptfoo": "full",
        "Garak": "full",
        "Inspect AI": "full",
        "PyRIT": "full",
    },
    "Utility-under-attack measurement": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "partial",
        "PyRIT": "none",
    },
    "Quality-aware scoring": {
        "ZIRAN": "full",
        "Promptfoo": "partial",
        "Garak": "partial",
        "Inspect AI": "full",
        "PyRIT": "partial",
    },
    "HTML/JSON report generation": {
        "ZIRAN": "full",
        "Promptfoo": "full",
        "Garak": "full",
        "Inspect AI": "full",
        "PyRIT": "partial",
    },
    "CI/CD integration": {
        "ZIRAN": "full",
        "Promptfoo": "full",
        "Garak": "full",
        "Inspect AI": "full",
        "PyRIT": "partial",
    },
    "Compliance framework plugins": {
        "ZIRAN": "none",
        "Promptfoo": "full",
        "Garak": "partial",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "Harm category taxonomy": {
        "ZIRAN": "full",
        "Promptfoo": "partial",
        "Garak": "full",
        "Inspect AI": "full",
        "PyRIT": "partial",
    },
    "Data exfiltration detection": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "partial",
        "Inspect AI": "none",
        "PyRIT": "none",
    },
    "Privilege escalation vectors": {
        "ZIRAN": "full",
        "Promptfoo": "none",
        "Garak": "none",
        "Inspect AI": "none",
        "PyRIT": "partial",
    },
}


def _score_to_value(score: str) -> float:
    """Convert capability score to numeric value."""
    return {"full": 1.0, "partial": 0.5, "none": 0.0, "planned": 0.25}.get(score, 0.0)


def collect_comparative_analysis() -> dict:
    """Collect comparative analysis data."""
    lib = get_attack_library()

    # Compute scores per tool
    tool_scores: dict[str, dict] = {}
    for tool in TOOLS:
        name = tool["name"]
        caps = {cap: CAPABILITY_MATRIX[cap][name] for cap in CAPABILITY_MATRIX}
        full_count = sum(1 for v in caps.values() if v == "full")
        partial_count = sum(1 for v in caps.values() if v == "partial")
        none_count = sum(1 for v in caps.values() if v == "none")
        weighted_score = sum(_score_to_value(v) for v in caps.values())

        tool_scores[name] = {
            **tool,
            "capabilities": caps,
            "full_count": full_count,
            "partial_count": partial_count,
            "none_count": none_count,
            "weighted_score": round(weighted_score, 1),
            "coverage_pct": round(weighted_score / len(CAPABILITY_MATRIX) * 100, 1),
        }

    # ZIRAN-specific strengths and gaps
    ziran_caps = tool_scores["ZIRAN"]["capabilities"]
    strengths = [cap for cap, score in ziran_caps.items() if score == "full"]
    gaps = [cap for cap, score in ziran_caps.items() if score in ("none", "partial")]

    # Unique to ZIRAN (full in ZIRAN, none/partial in all others)
    unique_strengths: list[str] = []
    for cap in CAPABILITY_MATRIX:
        if CAPABILITY_MATRIX[cap]["ZIRAN"] == "full":
            others_max = max(
                _score_to_value(CAPABILITY_MATRIX[cap][t["name"]])
                for t in TOOLS
                if t["name"] != "ZIRAN"
            )
            if others_max == 0.0:
                unique_strengths.append(cap)

    # Where others are stronger
    competitive_gaps: list[dict] = []
    for cap in CAPABILITY_MATRIX:
        ziran_score = _score_to_value(CAPABILITY_MATRIX[cap]["ZIRAN"])
        for tool in TOOLS:
            if tool["name"] == "ZIRAN":
                continue
            other_score = _score_to_value(CAPABILITY_MATRIX[cap][tool["name"]])
            if other_score > ziran_score:
                competitive_gaps.append(
                    {
                        "capability": cap,
                        "ziran": CAPABILITY_MATRIX[cap]["ZIRAN"],
                        "stronger_tool": tool["name"],
                        "their_score": CAPABILITY_MATRIX[cap][tool["name"]],
                    }
                )

    return {
        "tools": tool_scores,
        "capability_count": len(CAPABILITY_MATRIX),
        "ziran_vector_count": len(lib.vectors),
        "ziran_strengths": strengths,
        "ziran_gaps": gaps,
        "ziran_unique_strengths": unique_strengths,
        "competitive_gaps": competitive_gaps,
        "ranking": sorted(
            [(name, data["weighted_score"]) for name, data in tool_scores.items()],
            key=lambda x: -x[1],
        ),
    }


def generate_markdown(data: dict) -> str:
    """Generate markdown comparison report."""
    lines: list[str] = []
    lines.append("# Comparative Analysis: ZIRAN vs Other Tools")
    lines.append("")
    lines.append(
        "Feature comparison of ZIRAN against other AI security testing tools, "
        "based on published documentation and capabilities."
    )
    lines.append("")

    # Ranking
    lines.append("## Overall Ranking")
    lines.append("")
    lines.append("| Rank | Tool | Score | Coverage |")
    lines.append("|------|------|------:|----------|")
    for i, (name, score) in enumerate(data["ranking"], 1):
        tool_data = data["tools"][name]
        lines.append(
            f"| {i} | **{name}** | {score}/{data['capability_count']} | "
            f"{tool_data['coverage_pct']}% |"
        )
    lines.append("")

    # Capability matrix
    lines.append("## Capability Matrix")
    lines.append("")
    tool_names = [t["name"] for t in TOOLS]
    header = "| Capability | " + " | ".join(f"**{n}**" for n in tool_names) + " |"
    separator = "|" + "|".join(["---"] * (len(tool_names) + 1)) + "|"
    lines.append(header)
    lines.append(separator)

    icon_map = {
        "full": ":white_check_mark:",
        "partial": ":large_orange_diamond:",
        "none": ":x:",
        "planned": ":construction:",
    }

    for cap in CAPABILITY_MATRIX:
        cols = [icon_map.get(CAPABILITY_MATRIX[cap][n], "") for n in tool_names]
        lines.append(f"| {cap} | " + " | ".join(cols) + " |")
    lines.append("")

    # Unique strengths
    lines.append("## ZIRAN Unique Strengths")
    lines.append("")
    lines.append("Capabilities where ZIRAN is the only tool with full support:")
    lines.append("")
    for s in data["ziran_unique_strengths"]:
        lines.append(f"- **{s}**")
    lines.append("")

    # Competitive gaps
    lines.append("## Competitive Gaps")
    lines.append("")
    lines.append("Areas where other tools have stronger capabilities:")
    lines.append("")
    for gap in data["competitive_gaps"]:
        lines.append(
            f"- **{gap['capability']}**: "
            f"{gap['stronger_tool']} ({gap['their_score']}) "
            f"vs ZIRAN ({gap['ziran']})"
        )
    lines.append("")

    return "\n".join(lines)


def print_summary(data: dict) -> None:
    """Print human-readable comparative analysis."""
    print("Comparative Analysis: ZIRAN vs Other Tools")
    print("=" * 60)

    print("\nRanking:")
    for i, (name, score) in enumerate(data["ranking"], 1):
        tool = data["tools"][name]
        print(f"  {i}. {name}: {score}/{data['capability_count']} ({tool['coverage_pct']}%)")

    print(f"\nUnique ZIRAN strengths ({len(data['ziran_unique_strengths'])}):")
    for s in data["ziran_unique_strengths"]:
        print(f"  + {s}")

    print(f"\nCompetitive gaps ({len(data['competitive_gaps'])}):")
    for gap in data["competitive_gaps"]:
        print(f"  - {gap['capability']}: {gap['stronger_tool']} > ZIRAN")


def main() -> None:
    parser = argparse.ArgumentParser(description="Comparative analysis against other tools")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    parser.add_argument("--markdown", action="store_true", help="Output markdown report")
    args = parser.parse_args()

    data = collect_comparative_analysis()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    elif args.markdown:
        print(generate_markdown(data))
    else:
        print_summary(data)


if __name__ == "__main__":
    main()
