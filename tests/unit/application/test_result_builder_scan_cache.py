"""ResultBuilder ``metadata["scan_cache"]`` (spec 049)."""

from __future__ import annotations

from typing import Any

import pytest

from ziran.application.agent_scanner.result_builder import ResultBuilder
from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache, ScanCacheStats
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.domain.entities.attack import TokenUsage

pytestmark = pytest.mark.unit


def _build(**kwargs: Any) -> dict[str, Any]:
    result, _ = ResultBuilder(AttackKnowledgeGraph(), "Mock").build(
        campaign_id="c",
        phase_results=[],
        attack_results=[],
        campaign_tokens=TokenUsage(),
        coverage_value="standard",
        max_concurrent_attacks=1,
        duration=0.0,
        capabilities_count=0,
        **kwargs,
    )
    return result.metadata


def test_scan_cache_counts_in_metadata() -> None:
    cache = ScanCache(CacheContext(ziran_version="0", target_sha256="0" * 64))
    cache.stats = ScanCacheStats(executed=1, cached=4)
    assert _build(scan_cache=cache)["scan_cache"] == {"executed": 1, "cached": 4}


def test_absent_without_cache() -> None:
    assert "scan_cache" not in _build()
