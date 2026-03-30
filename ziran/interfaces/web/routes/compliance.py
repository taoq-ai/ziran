"""OWASP LLM Top 10 compliance matrix endpoint."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ziran.domain.entities.attack import OWASP_LLM_DESCRIPTIONS, OwaspLlmCategory
from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import ComplianceMapping, Finding
from ziran.interfaces.web.schemas import (
    ComplianceSummary,
    OwaspCategoryStatus,
    OwaspComplianceResponse,
)

router = APIRouter()


@router.get("/compliance/owasp", response_model=OwaspComplianceResponse)
async def owasp_compliance(
    db: Annotated[AsyncSession, Depends(get_db)],
    run_id: uuid.UUID | None = None,
) -> OwaspComplianceResponse:
    """Return OWASP LLM Top 10 coverage matrix data."""
    # Build base query joining findings → compliance_mappings
    base = (
        select(
            ComplianceMapping.control_id,
            Finding.severity,
            func.count().label("cnt"),
        )
        .join(Finding, ComplianceMapping.finding_id == Finding.id)
        .where(ComplianceMapping.framework == "owasp_llm")
    )

    if run_id:
        base = base.where(Finding.run_id == run_id)

    # Only count open findings for status determination
    base_open = base.where(Finding.status == "open")

    base = base.group_by(ComplianceMapping.control_id, Finding.severity)
    base_open = base_open.group_by(ComplianceMapping.control_id, Finding.severity)

    result = await db.execute(base)
    rows = result.all()

    # Also get open-only counts for status logic
    open_result = await db.execute(base_open)
    open_rows = open_result.all()

    # Aggregate by control_id
    all_counts: dict[str, dict[str, int]] = {}
    for control_id, sev, cnt in rows:
        all_counts.setdefault(control_id, {}).setdefault(sev, 0)
        all_counts[control_id][sev] += cnt

    open_counts: dict[str, dict[str, int]] = {}
    for control_id, sev, cnt in open_rows:
        open_counts.setdefault(control_id, {}).setdefault(sev, 0)
        open_counts[control_id][sev] += cnt

    # Build response for all 10 categories
    categories: list[OwaspCategoryStatus] = []
    tested = 0
    with_critical = 0
    with_findings = 0

    for cat in OwaspLlmCategory:
        control_id = cat.value
        by_severity = all_counts.get(control_id, {})
        open_by_severity = open_counts.get(control_id, {})
        finding_count = sum(by_severity.values())

        # Determine status based on OPEN findings
        open_count = sum(open_by_severity.values())
        has_critical_or_high = open_by_severity.get("critical", 0) + open_by_severity.get("high", 0)

        if finding_count == 0:
            status = "not_tested"
        elif open_count == 0:
            status = "pass"
            tested += 1
        elif has_critical_or_high > 0:
            status = "critical"
            tested += 1
            with_critical += 1
            with_findings += 1
        else:
            status = "warning"
            tested += 1
            with_findings += 1

        # Ensure all severity keys present
        full_severity = {
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "info": by_severity.get("info", 0),
        }

        categories.append(
            OwaspCategoryStatus(
                control_id=control_id,
                control_name=OWASP_LLM_DESCRIPTIONS.get(cat, control_id),
                description=cat.__doc__ or OWASP_LLM_DESCRIPTIONS.get(cat, ""),
                finding_count=finding_count,
                by_severity=full_severity,
                status=status,
            )
        )

    not_tested = 10 - tested

    return OwaspComplianceResponse(
        categories=categories,
        summary=ComplianceSummary(
            total_categories=10,
            tested=tested,
            not_tested=not_tested,
            with_critical=with_critical,
            with_findings=with_findings,
        ),
    )
