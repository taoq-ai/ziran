"""Tool Chain Analyzer — ZIRAN's unique differentiator.

Analyzes the attack knowledge graph to discover dangerous tool
combinations that enable multi-step exploitation.  While other
frameworks test individual prompts, ZIRAN reasons about the
*composition* of tools an agent has access to.

Example dangerous chain: ``read_file`` → ``http_request`` allows an
attacker to exfiltrate local file contents to an external server.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import networkx as nx

from ziran.application.knowledge_graph.chain_patterns import (
    ChainPatternInfo,
    ChainPatternRegistry,
)
from ziran.application.knowledge_graph.graph import NodeType
from ziran.domain.entities.capability import DangerousChain

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

logger = logging.getLogger(__name__)

# ── Dangerous pattern definitions ──────────────────────────────────────
# Loaded from chain_patterns.yaml via the ChainPatternRegistry.
# Keys are tuples of (source_tool, target_tool).
# Matching is *substring* based so that ``"read_file"`` matches
# tool IDs like ``"tool_read_file"`` or ``"fs_read_file"``.

DANGEROUS_PATTERNS: dict[tuple[str, str], ChainPatternInfo] = (
    ChainPatternRegistry.default().to_dangerous_patterns()
)

# ── Risk weights for score calculation ─────────────────────────────

_RISK_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}

_CHAIN_TYPE_MULTIPLIERS: dict[str, float] = {
    "direct": 1.0,
    "indirect": 0.8,
    "cycle": 0.9,
}


class ToolChainAnalyzer:
    """Analyzes the attack knowledge graph for dangerous tool chains.

    This is ZIRAN's unique value proposition: *tool-aware* security testing
    that detects dangerous tool combinations automatically rather than
    relying solely on per-prompt testing.

    The analyzer searches for:

    1. **Direct chains** — tool A has an edge to tool B, and (A, B) matches
       a known dangerous pattern.
    2. **Indirect chains** — tools A and B are connected through
       intermediate nodes (A → … → B) within a configurable hop limit.
    3. **Cycles** — circular chains (A → B → … → A) that enable
       repeated exploitation.

    Example::

        analyzer = ToolChainAnalyzer(graph)
        chains = analyzer.analyze()
        for c in chains:
            print(c.vulnerability_type, c.risk_score)
    """

    def __init__(
        self,
        graph: AttackKnowledgeGraph,
        *,
        custom_patterns_path: Path | None = None,
    ) -> None:
        self.graph = graph
        if custom_patterns_path is not None:
            custom = ChainPatternRegistry.from_yaml(custom_patterns_path)
            merged = ChainPatternRegistry.default().merge(custom)
            self._patterns = merged.to_dangerous_patterns()
        else:
            self._patterns = DANGEROUS_PATTERNS

    # ── Public API ─────────────────────────────────────────────────

    def analyze(self) -> list[DangerousChain]:
        """Run full chain analysis and return all dangerous chains found.

        Steps:
            1. Discover direct 2-tool chains (A → B).
            2. Discover indirect chains (A → … → B, up to 3 hops).
            3. Discover cycles (A → B → … → A).
            4. De-duplicate, score, and sort by risk.

        Returns:
            Sorted list of :class:`DangerousChain` objects (highest risk first).
        """
        chains: list[DangerousChain] = []

        chains.extend(self._find_direct_chains())
        chains.extend(self._find_indirect_chains(max_hops=3))
        chains.extend(self._find_chain_cycles())

        # Deduplicate by (tools tuple, vulnerability_type)
        seen: set[tuple[tuple[str, ...], str]] = set()
        unique: list[DangerousChain] = []
        for chain in chains:
            key = (tuple(chain.tools), chain.vulnerability_type)
            if key not in seen:
                seen.add(key)
                chain.risk_score = self._calculate_risk_score(chain)
                unique.append(chain)

        # Sort by risk score descending, then by risk_level severity
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda c: (-c.risk_score, risk_order.get(c.risk_level, 4)))

        logger.info(
            "Tool chain analysis complete: %d dangerous chains found "
            "(%d critical, %d high, %d medium)",
            len(unique),
            sum(1 for c in unique if c.risk_level == "critical"),
            sum(1 for c in unique if c.risk_level == "high"),
            sum(1 for c in unique if c.risk_level == "medium"),
        )

        return unique

    # ── Direct chains ──────────────────────────────────────────────

    def _find_direct_chains(self) -> list[DangerousChain]:
        """Find dangerous 2-tool chains where A → B exists in the graph."""
        chains: list[DangerousChain] = []
        tool_nodes = self._get_tool_nodes()

        for source_id, _source_data in tool_nodes:
            for target_id, _target_data in tool_nodes:
                if source_id == target_id:
                    continue
                if not self.graph.graph.has_edge(source_id, target_id):
                    continue

                pattern_info = self._match_pattern(source_id, target_id)
                if pattern_info is not None:
                    chains.append(
                        DangerousChain(
                            tools=[source_id, target_id],
                            risk_level=pattern_info["risk"],
                            vulnerability_type=pattern_info["type"],
                            exploit_description=pattern_info["description"],
                            remediation=pattern_info.get("remediation", ""),
                            graph_path=[source_id, target_id],
                            chain_type="direct",
                            evidence={"edge_exists": True},
                        )
                    )

        return chains

    # ── Indirect chains ────────────────────────────────────────────

    def _find_indirect_chains(self, max_hops: int = 3) -> list[DangerousChain]:
        """Find dangerous chains A → X → … → B via intermediate nodes."""
        chains: list[DangerousChain] = []
        tool_nodes = self._get_tool_nodes()

        for source_id, _ in tool_nodes:
            for target_id, _ in tool_nodes:
                if source_id == target_id:
                    continue

                # Skip if there's already a direct edge (handled above)
                if self.graph.graph.has_edge(source_id, target_id):
                    continue

                pattern_info = self._match_pattern(source_id, target_id)
                if pattern_info is None:
                    continue

                # Search for paths via intermediate nodes
                try:
                    paths = list(
                        nx.all_simple_paths(
                            self.graph.graph,
                            source_id,
                            target_id,
                            cutoff=max_hops,
                        )
                    )
                except (nx.NetworkXError, nx.NodeNotFound):
                    continue

                for path in paths:
                    if len(path) < 3:
                        continue  # must have at least 1 intermediate

                    chains.append(
                        DangerousChain(
                            tools=[source_id, target_id],
                            risk_level=pattern_info["risk"],
                            vulnerability_type=pattern_info["type"],
                            exploit_description=(
                                f"{pattern_info['description']} "
                                f"(via {len(path) - 2} intermediate node(s))"
                            ),
                            remediation=pattern_info.get("remediation", ""),
                            graph_path=path,
                            chain_type="indirect",
                            evidence={
                                "full_path": path,
                                "intermediate_nodes": path[1:-1],
                                "hops": len(path) - 1,
                            },
                        )
                    )

        return chains

    # ── Cycle detection ────────────────────────────────────────────

    def _find_chain_cycles(self) -> list[DangerousChain]:
        """Find cycles in the graph that involve dangerous tool pairs."""
        chains: list[DangerousChain] = []
        tool_ids = {nid for nid, _ in self._get_tool_nodes()}

        try:
            cycles: list[list[str]] = list(nx.simple_cycles(self.graph.graph))
        except nx.NetworkXError:
            return chains

        for cycle in cycles:
            # Only consider cycles that include tool nodes
            tools_in_cycle = [n for n in cycle if n in tool_ids]
            if len(tools_in_cycle) < 2:
                continue

            # Check consecutive tool pairs in the cycle for dangerous patterns
            full_cycle = [*cycle, cycle[0]]  # close the cycle
            for i in range(len(full_cycle) - 1):
                src, tgt = full_cycle[i], full_cycle[i + 1]
                if src not in tool_ids or tgt not in tool_ids:
                    continue

                pattern_info = self._match_pattern(src, tgt)
                if pattern_info is not None:
                    chains.append(
                        DangerousChain(
                            tools=tools_in_cycle,
                            risk_level=pattern_info["risk"],
                            vulnerability_type=pattern_info["type"],
                            exploit_description=(
                                f"{pattern_info['description']} "
                                f"(cyclical chain enables repeated exploitation)"
                            ),
                            remediation=pattern_info.get("remediation", ""),
                            graph_path=cycle,
                            chain_type="cycle",
                            evidence={
                                "cycle": cycle,
                                "cycle_length": len(cycle),
                            },
                        )
                    )

        return chains

    # ── Scoring ────────────────────────────────────────────────────

    def _calculate_risk_score(self, chain: DangerousChain) -> float:
        """Calculate a 0.0-1.0 risk score for a chain.

        Factors:
        - Base weight from risk level (critical=1.0 … low=0.25).
        - Multiplier from chain type (direct > cycle > indirect).
        - Bonus for chains involving nodes with high graph centrality.
        """
        base = _RISK_WEIGHTS.get(chain.risk_level, 0.5)
        multiplier = _CHAIN_TYPE_MULTIPLIERS.get(chain.chain_type, 1.0)

        # Centrality bonus: if any tool in the chain is a high-centrality node
        centrality_bonus = 0.0
        if self.graph.graph.number_of_nodes() > 1:
            try:
                bc: dict[str, float] = nx.betweenness_centrality(self.graph.graph)
                for tool in chain.tools:
                    if tool in bc:
                        centrality_bonus = max(centrality_bonus, bc[tool] * 0.15)
            except nx.NetworkXError:
                pass

        score = base * multiplier + centrality_bonus
        return min(1.0, round(score, 3))

    # ── Helpers ────────────────────────────────────────────────────

    def _get_tool_nodes(self) -> list[tuple[str, dict[str, Any]]]:
        """Return all tool and capability nodes in the graph."""
        return [
            (n, d)
            for n, d in self.graph.graph.nodes(data=True)
            if d.get("node_type") in (NodeType.TOOL, NodeType.CAPABILITY)
        ]

    def _match_pattern(
        self,
        source_id: str,
        target_id: str,
    ) -> ChainPatternInfo | None:
        """Check whether a (source, target) pair matches any dangerous pattern.

        Uses *substring* matching so that ``"tool_read_file"`` matches
        the pattern key ``"read_file"``.
        """
        source_lower = source_id.lower()
        target_lower = target_id.lower()

        for (pat_src, pat_tgt), info in self._patterns.items():
            if pat_src in source_lower and pat_tgt in target_lower:
                return info

        return None
