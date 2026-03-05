"""Unit tests for finding deduplication — embedding-based clustering."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.domain.entities.attack import AttackCategory, AttackResult
from ziran.domain.entities.pentest import DeduplicatedFinding

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_result(
    vector_id: str = "vec_001",
    vector_name: str = "Test Vector",
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    severity: str = "high",
    successful: bool = True,
    agent_response: str = "I leaked data",
    owasp: list | None = None,
    evidence: dict | None = None,
) -> AttackResult:
    return AttackResult(
        vector_id=vector_id,
        vector_name=vector_name,
        category=category,
        severity=severity,
        successful=successful,
        agent_response=agent_response,
        evidence=evidence or {"response": agent_response},
        owasp_mapping=owasp or [],
    )


def _mock_llm_client() -> MagicMock:
    client = MagicMock()
    client.complete = AsyncMock()
    return client


# ──────────────────────────────────────────────────────────────────────
# FindingDeduplicator._fallback_embedding
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestFallbackEmbedding:
    """Tests for the hash-based fallback embedding."""

    def test_produces_correct_dimension(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        emb = FindingDeduplicator._fallback_embedding("hello world", dim=64)
        assert len(emb) == 64
        assert all(isinstance(v, float) for v in emb)
        assert all(0.0 <= v <= 1.0 for v in emb)

    def test_deterministic(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        e1 = FindingDeduplicator._fallback_embedding("same text")
        e2 = FindingDeduplicator._fallback_embedding("same text")
        assert e1 == e2

    def test_different_texts_differ(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        e1 = FindingDeduplicator._fallback_embedding("text a")
        e2 = FindingDeduplicator._fallback_embedding("text b")
        assert e1 != e2

    def test_custom_dimension(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        emb = FindingDeduplicator._fallback_embedding("hello", dim=10)
        assert len(emb) == 10


# ──────────────────────────────────────────────────────────────────────
# FindingDeduplicator._cosine_similarity
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestCosineSimilarity:
    """Tests for cosine similarity computation."""

    def test_identical_vectors(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        sim = FindingDeduplicator._cosine_similarity([1, 0, 0], [1, 0, 0])
        assert abs(sim - 1.0) < 1e-6

    def test_orthogonal_vectors(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        sim = FindingDeduplicator._cosine_similarity([1, 0], [0, 1])
        assert abs(sim - 0.0) < 1e-6

    def test_opposite_vectors(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        sim = FindingDeduplicator._cosine_similarity([1, 0], [-1, 0])
        assert abs(sim - (-1.0)) < 1e-6

    def test_zero_vector(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        sim = FindingDeduplicator._cosine_similarity([0, 0, 0], [1, 2, 3])
        assert sim == 0.0

    def test_similar_vectors(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        sim = FindingDeduplicator._cosine_similarity([1, 2, 3], [1.1, 2.1, 3.1])
        assert sim > 0.99


# ──────────────────────────────────────────────────────────────────────
# FindingDeduplicator._finding_text
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestFindingText:
    """Tests for the text representation used for embedding."""

    def test_includes_category_and_vector_name(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        result = _make_result(
            vector_name="Injection Test",
            category=AttackCategory.PROMPT_INJECTION,
        )
        text = dedup._finding_text(result)
        assert "prompt_injection" in text
        assert "Injection Test" in text

    def test_includes_severity(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        result = _make_result(severity="critical")
        text = dedup._finding_text(result)
        assert "critical" in text

    def test_includes_response_preview(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        result = _make_result(agent_response="Leaked secret key: abc123")
        text = dedup._finding_text(result)
        assert "Leaked secret key" in text


# ──────────────────────────────────────────────────────────────────────
# FindingDeduplicator.deduplicate
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDeduplicate:
    """Tests for the main deduplication pipeline."""

    async def test_empty_results(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        findings = await dedup.deduplicate([])
        assert findings == []

    async def test_no_successful_results(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        results = [_make_result(successful=False)]
        findings = await dedup.deduplicate(results)
        assert findings == []

    async def test_single_result_to_single_finding(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        results = [_make_result(vector_name="PI Test", severity="high")]
        # Use fallback embeddings by making _embed_text use the fallback
        dedup._embed_text = AsyncMock(side_effect=lambda t: dedup._fallback_embedding(t))

        findings = await dedup.deduplicate(results)

        assert len(findings) == 1
        assert findings[0].canonical_title == "PI Test"
        assert findings[0].severity == "high"
        assert findings[0].confidence == 1.0  # Single-result cluster

    async def test_similar_results_clustered(self) -> None:
        """Two results with identical text should cluster together."""
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        results = [
            _make_result(vector_id="v1", vector_name="PI Test A", agent_response="leaked data"),
            _make_result(vector_id="v2", vector_name="PI Test B", agent_response="leaked data"),
        ]
        # Force identical fallback embeddings by patching _embed_text
        fixed_emb = [0.5] * 64
        dedup._embed_text = AsyncMock(return_value=fixed_emb)

        findings = await dedup.deduplicate(results, threshold=0.85)
        # With identical embeddings, cos-sim = 1.0 => should cluster
        assert len(findings) == 1
        assert len(findings[0].attack_result_ids) == 2
        assert findings[0].confidence == 0.9  # Multi-result cluster

    async def test_dissimilar_results_separate(self) -> None:
        """Results with very different embeddings should stay separate."""
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        results = [
            _make_result(vector_id="v1", vector_name="PI Test"),
            _make_result(
                vector_id="v2",
                vector_name="Data Exfil",
                category=AttackCategory.DATA_EXFILTRATION,
            ),
        ]
        # Produce orthogonal embeddings
        emb_a = [1.0, 0.0, 0.0, 0.0]
        emb_b = [0.0, 1.0, 0.0, 0.0]
        call_count = 0

        async def _alternating_embed(_text: str) -> list[float]:
            nonlocal call_count
            call_count += 1
            return emb_a if call_count % 2 == 1 else emb_b

        dedup._embed_text = _alternating_embed  # type: ignore[assignment]

        findings = await dedup.deduplicate(results, threshold=0.85)
        assert len(findings) == 2

    async def test_highest_severity_wins(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        dedup = FindingDeduplicator(llm_client=_mock_llm_client())
        results = [
            _make_result(vector_id="v1", severity="medium"),
            _make_result(vector_id="v2", severity="critical"),
        ]
        fixed_emb = [0.5] * 64
        dedup._embed_text = AsyncMock(return_value=fixed_emb)

        findings = await dedup.deduplicate(results, threshold=0.85)
        assert len(findings) == 1
        assert findings[0].severity == "critical"


# ──────────────────────────────────────────────────────────────────────
# FindingDeduplicator.merge_findings
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestMergeFindings:
    """Tests for cross-scan finding merger."""

    def test_empty_existing(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        new = [
            DeduplicatedFinding(
                canonical_title="New",
                canonical_description="New finding",
                severity="high",
            )
        ]
        merged = FindingDeduplicator.merge_findings([], new)
        assert len(merged) == 1
        assert merged[0].canonical_title == "New"

    def test_empty_new(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        existing = [
            DeduplicatedFinding(
                canonical_title="Old",
                canonical_description="Old finding",
                severity="medium",
            )
        ]
        merged = FindingDeduplicator.merge_findings(existing, [])
        assert len(merged) == 1

    def test_similar_findings_merge(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        emb = [1.0, 0.0, 0.0]
        existing = [
            DeduplicatedFinding(
                canonical_title="PI Vuln",
                canonical_description="Prompt injection",
                severity="medium",
                embedding=emb,
                attack_result_ids=["v1"],
            )
        ]
        new = [
            DeduplicatedFinding(
                canonical_title="PI Vuln 2",
                canonical_description="Another PI",
                severity="high",
                embedding=emb,
                attack_result_ids=["v2"],
            )
        ]
        merged = FindingDeduplicator.merge_findings(existing, new, threshold=0.85)
        assert len(merged) == 1
        assert merged[0].severity == "high"  # Highest wins
        assert "v1" in merged[0].attack_result_ids
        assert "v2" in merged[0].attack_result_ids

    def test_dissimilar_findings_stay_separate(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        existing = [
            DeduplicatedFinding(
                canonical_title="PI",
                canonical_description="PI",
                severity="high",
                embedding=[1.0, 0.0, 0.0],
            )
        ]
        new = [
            DeduplicatedFinding(
                canonical_title="DE",
                canonical_description="Data exfil",
                severity="critical",
                embedding=[0.0, 1.0, 0.0],
            )
        ]
        merged = FindingDeduplicator.merge_findings(existing, new, threshold=0.85)
        assert len(merged) == 2

    def test_merge_without_embeddings_appends(self) -> None:
        from ziran.application.pentesting.deduplication import FindingDeduplicator

        existing = [
            DeduplicatedFinding(
                canonical_title="A",
                canonical_description="A",
                severity="low",
                embedding=[],
            )
        ]
        new = [
            DeduplicatedFinding(
                canonical_title="B",
                canonical_description="B",
                severity="medium",
                embedding=[],
            )
        ]
        merged = FindingDeduplicator.merge_findings(existing, new)
        assert len(merged) == 2  # Can't compare, so appended
