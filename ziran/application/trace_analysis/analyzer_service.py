"""Trace analysis service.

Orchestrates trace ingestion and chain analysis to produce
:class:`CampaignResult` objects from production trace data.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from ziran.application.knowledge_graph.chain_analyzer import (
    ToolChainAnalyzer,
)
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.capability import DangerousChain
    from ziran.domain.entities.trace import TraceSession
    from ziran.domain.ports.trace_ingestor import TraceIngestor

logger = logging.getLogger(__name__)


class AnalyzerService:
    """Analyze production traces for dangerous tool chains.

    Builds a temporary :class:`AttackKnowledgeGraph` per session,
    runs the existing :class:`ToolChainAnalyzer`, and annotates
    findings with trace metadata.
    """

    def __init__(self, ingestor: TraceIngestor) -> None:
        self._ingestor = ingestor

    async def analyze(self, source: Path | str, **kwargs: Any) -> CampaignResult:
        """Analyze traces and produce findings.

        Args:
            source: Path or identifier passed to the ingestor.
            **kwargs: Extra arguments forwarded to the ingestor.

        Returns:
            A :class:`CampaignResult` with ``source="trace-analysis"``.
        """
        sessions = await self._ingestor.ingest(source, **kwargs)
        all_chains: list[DangerousChain] = []

        for session in sessions:
            chains = self._analyze_session(session)
            all_chains.extend(chains)

        aggregated = self._aggregate_chains(all_chains)

        campaign_id = f"trace-{uuid.uuid4().hex[:12]}"
        total_vulns = len(aggregated)
        has_critical = any(c.is_critical for c in aggregated)

        # Build a synthetic PhaseResult for the analysis
        phase_result = PhaseResult(
            phase=ScanPhase.VULNERABILITY_DISCOVERY,
            success=True,
            artifacts={
                "sessions_analyzed": len(sessions),
                "chains_found": len(aggregated),
            },
            trust_score=1.0,
            discovered_capabilities=[tc.tool_name for s in sessions for tc in s.tool_calls],
            vulnerabilities_found=[c.vulnerability_type for c in aggregated],
            duration_seconds=0.0,
        )

        return CampaignResult(
            campaign_id=campaign_id,
            target_agent="trace-analysis",
            phases_executed=[phase_result],
            total_vulnerabilities=total_vulns,
            critical_paths=[c.graph_path for c in aggregated],
            final_trust_score=1.0,
            success=has_critical,
            dangerous_tool_chains=[c.model_dump() for c in aggregated],
            critical_chain_count=sum(1 for c in aggregated if c.is_critical),
            source="trace-analysis",
            metadata={
                "sessions_analyzed": len(sessions),
                "trace_source": (sessions[0].source if sessions else "unknown"),
            },
        )

    def _analyze_session(self, session: TraceSession) -> list[DangerousChain]:
        """Build a temp graph for one session and run chain analysis."""
        if len(session.tool_calls) < 2:
            return []

        graph = AttackKnowledgeGraph()

        # Add tool nodes and CAN_CHAIN_TO edges for consecutive calls
        for i, call in enumerate(session.tool_calls):
            graph.add_tool(call.tool_name)
            if i > 0:
                prev = session.tool_calls[i - 1]
                graph.add_tool_chain(
                    [prev.tool_name, call.tool_name],
                    risk_score=0.5,
                )

        analyzer = ToolChainAnalyzer(graph)
        chains = analyzer.analyze()

        # Annotate with trace metadata
        for chain in chains:
            chain.observed_in_production = True
            chain.trace_source = session.source
            chain.first_seen = session.start_time
            chain.last_seen = session.end_time
            chain.occurrence_count = 1

        return chains

    def _aggregate_chains(self, chains: list[DangerousChain]) -> list[DangerousChain]:
        """Deduplicate and aggregate chains across sessions.

        Chains with the same ``(tools, vulnerability_type)`` key are
        merged: occurrence counts sum, time bounds widen.
        """
        seen: dict[tuple[tuple[str, ...], str], DangerousChain] = {}

        for chain in chains:
            key = (tuple(chain.tools), chain.vulnerability_type)
            if key in seen:
                existing = seen[key]
                existing.occurrence_count += chain.occurrence_count
                if (
                    chain.first_seen
                    and existing.first_seen
                    and chain.first_seen < existing.first_seen
                ):
                    existing.first_seen = chain.first_seen
                if chain.last_seen and existing.last_seen and chain.last_seen > existing.last_seen:
                    existing.last_seen = chain.last_seen
                # Keep the higher risk score
                existing.risk_score = max(existing.risk_score, chain.risk_score)
            else:
                seen[key] = chain

        result = list(seen.values())
        result.sort(key=lambda c: -c.risk_score)
        return result
