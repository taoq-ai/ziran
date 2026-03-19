"""Run the ground truth benchmark and report accuracy metrics.

Evaluates ZIRAN's offline detection components against the labeled
ground truth dataset:

  1. **Chain analyzer** — builds a knowledge graph from each agent's
     tools, runs the chain analyzer, and compares discovered chains
     against expected chains in each scenario.
  2. **Skill CVE matcher** — runs SkillCVEDatabase.check_agent()
     against each agent's tools and compares matches to the agent's
     known_vulnerabilities.
  3. **Tool classifier** — classifies each agent tool and compares
     the risk tier to the declared risk_level.

Outputs per-component precision, recall, F1 and an overall summary.

Usage:
    uv run python benchmarks/ground_truth/run.py
"""

from __future__ import annotations

import sys
from collections import defaultdict
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

from benchmarks.ground_truth.schema import (
    AgentDefinition,
    AgentToolConfig,
    GroundTruthScenario,
)

GROUND_TRUTH_DIR = Path(__file__).resolve().parent
AGENTS_DIR = GROUND_TRUTH_DIR / "agents"
SCENARIOS_DIR = GROUND_TRUTH_DIR / "scenarios"
CATEGORIES = ["tool_chain", "side_effect", "campaign"]


# ── Helpers ────────────────────────────────────────────────────────────


def _load_yaml(path: Path) -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def load_agents() -> dict[str, AgentDefinition]:
    agents: dict[str, AgentDefinition] = {}
    for path in sorted(AGENTS_DIR.glob("*.yaml")):
        data = _load_yaml(path)
        agent = AgentDefinition(**data)
        agents[agent.agent_id] = agent
    return agents


def load_scenarios() -> list[GroundTruthScenario]:
    scenarios: list[GroundTruthScenario] = []
    for category in CATEGORIES:
        cat_dir = SCENARIOS_DIR / category
        if not cat_dir.exists():
            continue
        for path in sorted(cat_dir.glob("*.yaml")):
            data = _load_yaml(path)
            scenarios.append(GroundTruthScenario(**data))
    return scenarios


# ── Metrics ────────────────────────────────────────────────────────────


class Metrics:
    """Accumulates TP/FP/FN counts and computes precision/recall/F1."""

    def __init__(self) -> None:
        self.tp = 0
        self.fp = 0
        self.fn = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }

    def __repr__(self) -> str:
        return (
            f"TP={self.tp} FP={self.fp} FN={self.fn} "
            f"P={self.precision:.2%} R={self.recall:.2%} F1={self.f1:.2%}"
        )


# ── 1. Chain Analyzer Benchmark ───────────────────────────────────────


def _build_graph_for_agent(
    tools: list[AgentToolConfig],
) -> Any:
    """Build an AttackKnowledgeGraph with all tool pairs connected."""
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

    graph = AttackKnowledgeGraph()
    for tool in tools:
        graph.add_tool(tool.id)
    # Connect every pair — the agent can invoke any tool after any other
    for a, b in combinations(tools, 2):
        graph.add_tool_chain([a.id, b.id], risk_score=0.5)
        graph.add_tool_chain([b.id, a.id], risk_score=0.5)
    return graph


def _tool_keywords(tool_id: str) -> set[str]:
    """Split a tool ID into keywords: 'mcp_read_file' → {'mcp', 'read', 'file'}."""
    import re

    return {t for t in re.split(r"[_\-\s./]+", tool_id.lower()) if len(t) > 1}


def _tool_match(expected: str, found: str) -> bool:
    """Check if a single expected tool matches a found tool.

    Uses substring matching first, then keyword overlap.  For keyword
    overlap, at least half the expected keywords must appear in (or
    contain) at least one found keyword.  This handles naming variants
    like ``'http_request'`` matching ``'requests_get'`` (shared
    ``'request'``/``'requests'`` root) even when ``'http'`` has no
    counterpart.
    """
    exp_lower = expected.lower()
    found_lower = found.lower()
    # Strategy 1: direct substring
    if exp_lower in found_lower or found_lower in exp_lower:
        return True
    # Strategy 2: keyword overlap — at least half of expected keywords
    # must appear in some found keyword (via substring containment)
    exp_kw = _tool_keywords(expected)
    found_kw = _tool_keywords(found)
    if not exp_kw:
        return False
    hits = sum(1 for ek in exp_kw if any(ek in fk or fk in ek for fk in found_kw))
    return hits >= max(1, len(exp_kw) // 2)


def _chain_matches(found_tools: list[str], expected_tools: list[str]) -> bool:
    """Check if a found chain matches an expected chain.

    Each expected tool must match at least one found tool (using
    substring or keyword overlap matching).
    """
    if len(found_tools) < len(expected_tools):
        return False
    return all(any(_tool_match(exp, ft) for ft in found_tools) for exp in expected_tools)


def benchmark_chain_analyzer(
    agents: dict[str, AgentDefinition],
    scenarios: list[GroundTruthScenario],
) -> Metrics:
    """Evaluate the chain analyzer against ground truth expected_chains."""
    from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer

    metrics = Metrics()
    details: list[str] = []

    for scenario in scenarios:
        expected_chains = scenario.ground_truth.expected_chains
        if not expected_chains:
            continue

        agent = agents.get(scenario.agent_ref)
        if agent is None:
            continue

        graph = _build_graph_for_agent(agent.tools)
        analyzer = ToolChainAnalyzer(graph)
        found_chains = analyzer.analyze()
        found_tool_lists = [c.tools for c in found_chains]

        for expected in expected_chains:
            matched = any(_chain_matches(found, expected.tools) for found in found_tool_lists)
            if matched:
                metrics.tp += 1
            else:
                metrics.fn += 1
                details.append(
                    f"  MISS {scenario.scenario_id}: expected chain {expected.tools} not found"
                )

        # Count found chains that don't match any expected chain as FP
        # (only for TP scenarios where we have expectations)
        if scenario.ground_truth.label == "true_negative":
            for found in found_chains:
                metrics.fp += 1
                details.append(
                    f"  FP   {scenario.scenario_id}: unexpected chain {found.tools} on safe agent"
                )

    print("\n── Chain Analyzer ──────────────────────────────────────")
    print(f"  {metrics}")
    if details:
        print()
        for d in details[:20]:
            print(d)
        if len(details) > 20:
            print(f"  ... and {len(details) - 20} more")

    return metrics


# ── 2. Skill CVE Matcher Benchmark ────────────────────────────────────


def _is_cve_reference(ref: str) -> bool:
    """Check if a reference is a CVE or DESIGN-RISK ID (matchable by check_agent).

    Non-CVE references like 'OWASP LLM06', 'Agent Security Bench', or
    'chain_patterns cicd_pipeline' are informational labels that cannot
    be matched by the CVE database and should be excluded from scoring.
    """
    return ref.startswith(("CVE-", "DESIGN-RISK-")) and " " not in ref


def benchmark_skill_cve(
    agents: dict[str, AgentDefinition],
) -> Metrics:
    """Evaluate SkillCVEDatabase.check_agent() against known_vulnerabilities."""
    from ziran.application.skill_cve import SkillCVEDatabase
    from ziran.domain.entities.capability import AgentCapability, CapabilityType

    db = SkillCVEDatabase()
    metrics = Metrics()
    details: list[str] = []

    for agent_id, agent in agents.items():
        # Convert agent tools to AgentCapability objects
        caps = [
            AgentCapability(
                id=tool.id,
                name=tool.name,
                type=CapabilityType.TOOL,
                description=tool.description,
                dangerous=tool.risk_level in ("critical", "high"),
            )
            for tool in agent.tools
        ]

        found_cves = db.check_agent(caps)
        found_ids = {cve.cve_id for cve in found_cves}

        # Only score references that are actual CVE/DESIGN-RISK IDs
        expected_refs = {
            v.reference for v in agent.known_vulnerabilities if _is_cve_reference(v.reference)
        }

        # TP: found CVEs that match expected references
        for ref in expected_refs:
            if ref in found_ids:
                metrics.tp += 1
            else:
                metrics.fn += 1
                details.append(f"  MISS {agent_id}: expected {ref} not found by check_agent()")

        # FP: found CVEs not in expected references (only for safe agents)
        if not agent.known_vulnerabilities:
            for cve_id in found_ids:
                metrics.fp += 1
                details.append(f"  FP   {agent_id}: unexpected match {cve_id} on safe agent")

    print("\n── Skill CVE Matcher ───────────────────────────────────")
    print(f"  {metrics}")
    if details:
        print()
        for d in details[:20]:
            print(d)
        if len(details) > 20:
            print(f"  ... and {len(details) - 20} more")

    return metrics


# ── 3. Tool Classifier Benchmark ──────────────────────────────────────


def benchmark_tool_classifier(
    agents: dict[str, AgentDefinition],
) -> Metrics:
    """Evaluate tool_classifier.classify_tool() against declared risk levels."""
    from ziran.domain.tool_classifier import classify_tool

    metrics = Metrics()
    details: list[str] = []

    # Track per-risk-level accuracy
    level_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})

    for agent in agents.values():
        for tool in agent.tools:
            classification = classify_tool(tool.id)
            declared = tool.risk_level
            predicted = classification.risk

            level_counts[declared]["total"] += 1

            # For metrics: dangerous = critical or high
            declared_dangerous = declared in ("critical", "high")
            predicted_dangerous = predicted in ("critical", "high")

            if declared_dangerous and predicted_dangerous:
                metrics.tp += 1
                level_counts[declared]["correct"] += 1
            elif not declared_dangerous and not predicted_dangerous:
                level_counts[declared]["correct"] += 1
            elif predicted_dangerous and not declared_dangerous:
                metrics.fp += 1
                details.append(f"  FP   {tool.id}: classified as {predicted}, declared {declared}")
            else:
                metrics.fn += 1
                details.append(f"  MISS {tool.id}: classified as {predicted}, declared {declared}")

    print("\n── Tool Classifier ────────────────────────────────────")
    print(f"  {metrics}")
    print()
    print("  Per-level accuracy:")
    for level in ("critical", "high", "medium", "low"):
        counts = level_counts.get(level)
        if counts and counts["total"] > 0:
            acc = counts["correct"] / counts["total"]
            print(f"    {level:10s}: {counts['correct']}/{counts['total']} ({acc:.0%})")
    if details:
        print()
        for d in details[:20]:
            print(d)
        if len(details) > 20:
            print(f"  ... and {len(details) - 20} more")

    return metrics


# ── 4. Scenario-Level Verdict Benchmark ───────────────────────────────


def benchmark_scenario_verdict(
    agents: dict[str, AgentDefinition],
    scenarios: list[GroundTruthScenario],
) -> Metrics:
    """Evaluate whether ZIRAN would flag each scenario correctly.

    For each scenario, checks:
    - TP scenarios: does the agent have dangerous chains OR known CVE matches?
    - TN scenarios: does the safe agent avoid false alarms?
    """
    from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
    from ziran.application.skill_cve import SkillCVEDatabase
    from ziran.domain.entities.capability import AgentCapability, CapabilityType

    db = SkillCVEDatabase()
    metrics = Metrics()
    details: list[str] = []

    for scenario in scenarios:
        agent = agents.get(scenario.agent_ref)
        if agent is None:
            continue

        # Build chain analysis
        graph = _build_graph_for_agent(agent.tools)
        analyzer = ToolChainAnalyzer(graph)
        found_chains = analyzer.analyze()

        # Check CVEs
        caps = [
            AgentCapability(
                id=tool.id,
                name=tool.name,
                type=CapabilityType.TOOL,
                dangerous=tool.risk_level in ("critical", "high"),
            )
            for tool in agent.tools
        ]
        found_cves = db.check_agent(caps)

        # Verdict: would ZIRAN flag this agent?
        would_flag = len(found_chains) > 0 or len(found_cves) > 0

        is_tp = scenario.ground_truth.label == "true_positive"

        if is_tp and would_flag:
            metrics.tp += 1
        elif is_tp and not would_flag:
            metrics.fn += 1
            details.append(f"  MISS {scenario.scenario_id}: TP not flagged")
        elif not is_tp and not would_flag:
            pass  # True negative — correct, not counted in P/R
        elif not is_tp and would_flag:
            metrics.fp += 1
            details.append(
                f"  FP   {scenario.scenario_id}: TN incorrectly flagged "
                f"(chains={len(found_chains)}, cves={len(found_cves)})"
            )

    print("\n── Scenario-Level Verdict ──────────────────────────────")
    print(f"  {metrics}")
    if details:
        print()
        for d in details[:30]:
            print(d)
        if len(details) > 30:
            print(f"  ... and {len(details) - 30} more")

    return metrics


# ── Main ───────────────────────────────────────────────────────────────


def main() -> int:
    """Run all benchmarks and print summary."""
    print("=" * 60)
    print("GROUND TRUTH BENCHMARK — ACCURACY RESULTS")
    print("=" * 60)

    agents = load_agents()
    scenarios = load_scenarios()

    tp_count = sum(1 for s in scenarios if s.ground_truth.label == "true_positive")
    tn_count = sum(1 for s in scenarios if s.ground_truth.label == "true_negative")
    print(
        f"\nDataset: {len(agents)} agents, {len(scenarios)} scenarios ({tp_count} TP, {tn_count} TN)"
    )

    # Run benchmarks
    chain_metrics = benchmark_chain_analyzer(agents, scenarios)
    cve_metrics = benchmark_skill_cve(agents)
    tool_metrics = benchmark_tool_classifier(agents)
    verdict_metrics = benchmark_scenario_verdict(agents, scenarios)

    # Summary table
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"{'Component':<25s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s}")
    print("-" * 55)
    for name, m in [
        ("Chain Analyzer", chain_metrics),
        ("Skill CVE Matcher", cve_metrics),
        ("Tool Classifier", tool_metrics),
        ("Scenario Verdict", verdict_metrics),
    ]:
        print(f"{name:<25s} {m.precision:>9.1%} {m.recall:>9.1%} {m.f1:>9.1%}")
    print("-" * 55)

    # Overall (macro average)
    all_metrics = [chain_metrics, cve_metrics, tool_metrics, verdict_metrics]
    avg_p = sum(m.precision for m in all_metrics) / len(all_metrics)
    avg_r = sum(m.recall for m in all_metrics) / len(all_metrics)
    avg_f1 = sum(m.f1 for m in all_metrics) / len(all_metrics)
    print(f"{'Macro Average':<25s} {avg_p:>9.1%} {avg_r:>9.1%} {avg_f1:>9.1%}")
    print("=" * 60)

    # Save results to benchmarks/results/
    results_dir = Path(__file__).resolve().parent.parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC)

    # Build markdown report
    components = [
        ("Chain Analyzer", chain_metrics),
        ("Skill CVE Matcher", cve_metrics),
        ("Tool Classifier", tool_metrics),
        ("Scenario Verdict", verdict_metrics),
    ]

    lines = [
        "# Ground Truth Benchmark Results",
        "",
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"**Dataset:** {len(agents)} agents, {len(scenarios)} scenarios "
        f"({tp_count} TP, {tn_count} TN)",
        "",
        "## Summary",
        "",
        "| Component | TP | FP | FN | Precision | Recall | F1 |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]

    for name, m in components:
        lines.append(
            f"| {name} | {m.tp} | {m.fp} | {m.fn} "
            f"| {m.precision:.1%} | {m.recall:.1%} | {m.f1:.1%} |"
        )

    lines.append(
        f"| **Macro Average** | | | | **{avg_p:.1%}** | **{avg_r:.1%}** | **{avg_f1:.1%}** |"
    )
    lines.append("")

    md_content = "\n".join(lines) + "\n"

    # Write timestamped result and latest
    filename = f"ground_truth_{now.strftime('%Y%m%d_%H%M%S')}.md"
    result_path = results_dir / filename
    result_path.write_text(md_content)
    repo_root = Path(__file__).resolve().parent.parent.parent
    print(f"\nResults saved to {result_path.relative_to(repo_root)}")

    latest_path = results_dir / "ground_truth_latest.md"
    latest_path.write_text(md_content)

    return 0


if __name__ == "__main__":
    sys.exit(main())
