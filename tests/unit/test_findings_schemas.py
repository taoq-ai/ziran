"""Unit tests for findings-related Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ziran.interfaces.web.schemas import (
    BulkStatusResponse,
    BulkStatusUpdate,
    FindingDetail,
    FindingListResponse,
    FindingStats,
    FindingStatusUpdate,
    FindingSummary,
    OwaspCategoryStatus,
    OwaspComplianceResponse,
)

# Rebuild models so forward-referenced `uuid.UUID` / `datetime` types resolve.
FindingSummary.model_rebuild()
FindingDetail.model_rebuild()
BulkStatusUpdate.model_rebuild()
FindingListResponse.model_rebuild()


class TestFindingSummary:
    """Tests for FindingSummary schema."""

    def test_valid_serialization(self) -> None:
        data = {
            "id": uuid.uuid4(),
            "run_id": uuid.uuid4(),
            "vector_name": "Basic Prompt Injection",
            "category": "prompt_injection",
            "severity": "high",
            "owasp_category": "LLM01",
            "target_agent": "http://test:8080",
            "status": "open",
            "title": "Basic Prompt Injection (Prompt Injection)",
            "created_at": datetime.now(UTC),
        }
        summary = FindingSummary(**data)
        assert summary.severity == "high"
        assert summary.status == "open"

    def test_null_owasp_category(self) -> None:
        data = {
            "id": uuid.uuid4(),
            "run_id": uuid.uuid4(),
            "vector_name": "Test",
            "category": "unknown",
            "severity": "low",
            "owasp_category": None,
            "target_agent": "http://test:8080",
            "status": "open",
            "title": "Test",
            "created_at": datetime.now(UTC),
        }
        summary = FindingSummary(**data)
        assert summary.owasp_category is None


class TestFindingDetail:
    """Tests for FindingDetail schema."""

    def test_extends_summary(self) -> None:
        data = {
            "id": uuid.uuid4(),
            "run_id": uuid.uuid4(),
            "vector_name": "Test",
            "category": "test",
            "severity": "info",
            "owasp_category": None,
            "target_agent": "http://test:8080",
            "status": "open",
            "title": "Test Finding",
            "created_at": datetime.now(UTC),
            "fingerprint": "a" * 64,
            "vector_id": "test-001",
            "status_changed_at": None,
            "description": "A test finding",
            "remediation": "Fix it",
            "prompt_used": "Test prompt",
            "agent_response": "Test response",
            "evidence": {"key": "value"},
            "detection_metadata": {},
            "business_impact": ["financial_loss"],
            "compliance_mappings": [
                {
                    "framework": "owasp_llm",
                    "control_id": "LLM01",
                    "control_name": "Prompt Injection",
                }
            ],
        }
        detail = FindingDetail(**data)
        assert detail.fingerprint == "a" * 64
        assert len(detail.compliance_mappings) == 1


class TestFindingStatusUpdate:
    """Tests for FindingStatusUpdate schema."""

    def test_valid_status(self) -> None:
        update = FindingStatusUpdate(status="fixed")
        assert update.status == "fixed"

    def test_accepts_any_string(self) -> None:
        # Validation happens at the API level, not schema level
        update = FindingStatusUpdate(status="custom_status")
        assert update.status == "custom_status"


class TestBulkStatusUpdate:
    """Tests for BulkStatusUpdate schema."""

    def test_valid_bulk_update(self) -> None:
        update = BulkStatusUpdate(
            finding_ids=[uuid.uuid4(), uuid.uuid4()],
            status="ignored",
        )
        assert len(update.finding_ids) == 2

    def test_empty_ids_accepted(self) -> None:
        # Empty list is valid at schema level; API validates further
        update = BulkStatusUpdate(finding_ids=[], status="fixed")
        assert len(update.finding_ids) == 0


class TestBulkStatusResponse:
    """Tests for BulkStatusResponse schema."""

    def test_serialization(self) -> None:
        resp = BulkStatusResponse(updated=5, failed=0)
        assert resp.updated == 5


class TestFindingListResponse:
    """Tests for FindingListResponse schema."""

    def test_empty_list(self) -> None:
        resp = FindingListResponse(items=[], total=0, limit=25, offset=0)
        assert resp.total == 0
        assert resp.items == []


class TestFindingStats:
    """Tests for FindingStats schema."""

    def test_aggregation_shape(self) -> None:
        stats = FindingStats(
            total=100,
            by_severity={"critical": 5, "high": 20, "medium": 30, "low": 35, "info": 10},
            by_status={"open": 80, "fixed": 15, "false_positive": 3, "ignored": 2},
            by_category={"prompt_injection": 50, "tool_manipulation": 30, "data_exfiltration": 20},
            by_owasp={"LLM01": 30, "LLM07": 20},
        )
        assert stats.total == 100
        assert sum(stats.by_severity.values()) == 100


class TestOwaspComplianceResponse:
    """Tests for OwaspComplianceResponse schema."""

    def test_full_response(self) -> None:
        resp = OwaspComplianceResponse(
            categories=[
                OwaspCategoryStatus(
                    control_id="LLM01",
                    control_name="Prompt Injection",
                    description="Direct or indirect manipulation",
                    finding_count=25,
                    by_severity={"critical": 2, "high": 5, "medium": 10, "low": 8, "info": 0},
                    status="critical",
                )
            ],
            summary={
                "total_categories": 10,
                "tested": 7,
                "not_tested": 3,
                "with_critical": 2,
                "with_findings": 5,
            },
        )
        assert len(resp.categories) == 1
        assert resp.summary.total_categories == 10
