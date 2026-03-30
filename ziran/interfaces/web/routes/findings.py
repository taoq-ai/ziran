"""Findings CRUD, status management, and aggregate statistics."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import Finding
from ziran.interfaces.web.schemas import (
    BulkStatusResponse,
    BulkStatusUpdate,
    FindingDetail,
    FindingListResponse,
    FindingStats,
    FindingStatusUpdate,
    FindingSummary,
)

router = APIRouter()

_VALID_STATUSES = {"open", "fixed", "false_positive", "ignored"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_SORT_FIELDS = {"created_at", "severity", "status", "category"}


def _apply_filters(
    query: Any,
    *,
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
) -> Any:
    """Apply common filter parameters to a SQLAlchemy query."""
    if run_id:
        query = query.where(Finding.run_id == run_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    if owasp:
        query = query.where(Finding.owasp_category == owasp)
    if target:
        query = query.where(Finding.target_agent == target)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            Finding.title.ilike(pattern)
            | Finding.description.ilike(pattern)
            | Finding.vector_name.ilike(pattern)
        )
    return query


@router.get("/findings", response_model=FindingListResponse)
async def list_findings(
    db: Annotated[AsyncSession, Depends(get_db)],
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
    sort: str = "-created_at",
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> FindingListResponse:
    """List findings with filtering, search, and pagination."""
    query = select(Finding)
    count_query = select(func.count()).select_from(Finding)

    query = _apply_filters(
        query,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    count_query = _apply_filters(
        count_query,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )

    # Sorting
    desc = sort.startswith("-")
    sort_field_name = sort.lstrip("-")
    if sort_field_name not in _VALID_SORT_FIELDS:
        sort_field_name = "created_at"
        desc = True

    sort_col = getattr(Finding, sort_field_name)
    query = query.order_by(sort_col.desc() if desc else sort_col.asc())

    total_result = await db.execute(count_query)
    total: int = total_result.scalar_one()

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        items=[FindingSummary.model_validate(f) for f in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/stats", response_model=FindingStats)
async def finding_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
) -> FindingStats:
    """Aggregate finding statistics grouped by severity, status, category, and OWASP."""
    base = select(Finding)
    base = _apply_filters(
        base,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )

    # Total count
    count_q = select(func.count()).select_from(base.subquery())
    total: int = (await db.execute(count_q)).scalar_one()

    # Group by severity
    sev_q = select(Finding.severity, func.count()).select_from(
        base.subquery().join(Finding, Finding.id == base.subquery().c.id)
    )
    # Simpler approach: apply filters directly
    sev_q = select(Finding.severity, func.count()).group_by(Finding.severity)
    sev_q = _apply_filters(
        sev_q,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    sev_result = await db.execute(sev_q)
    by_severity: dict[str, int] = {str(k): int(v) for k, v in sev_result.all()}

    # Group by status
    stat_q = select(Finding.status, func.count()).group_by(Finding.status)
    stat_q = _apply_filters(
        stat_q,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    stat_result = await db.execute(stat_q)
    by_status: dict[str, int] = {str(k): int(v) for k, v in stat_result.all()}

    # Group by category
    cat_q = select(Finding.category, func.count()).group_by(Finding.category)
    cat_q = _apply_filters(
        cat_q,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    cat_result = await db.execute(cat_q)
    by_category: dict[str, int] = {str(k): int(v) for k, v in cat_result.all()}

    # Group by OWASP category
    owasp_q = (
        select(Finding.owasp_category, func.count())
        .where(Finding.owasp_category.isnot(None))
        .group_by(Finding.owasp_category)
    )
    owasp_q = _apply_filters(
        owasp_q,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    owasp_result = await db.execute(owasp_q)
    by_owasp: dict[str, int] = {str(k): int(v) for k, v in owasp_result.all()}

    return FindingStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_category=by_category,
        by_owasp=by_owasp,
    )


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> FindingDetail:
    """Get full finding detail including compliance mappings."""
    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.compliance_mappings))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingDetail.model_validate(finding)


@router.patch("/findings/{finding_id}/status", response_model=FindingSummary)
async def update_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> FindingSummary:
    """Update a finding's status."""
    if body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {body.status}")

    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    finding.status_changed_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(finding)

    return FindingSummary.model_validate(finding)


@router.post("/findings/bulk-status", response_model=BulkStatusResponse)
async def bulk_update_status(
    body: BulkStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> BulkStatusResponse:
    """Bulk update finding statuses."""
    if not body.finding_ids:
        raise HTTPException(status_code=422, detail="finding_ids must not be empty")
    if body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {body.status}")

    from sqlalchemy import update

    now = datetime.now(UTC)
    stmt = (
        update(Finding)
        .where(Finding.id.in_(body.finding_ids))
        .values(status=body.status, status_changed_at=now)
    )
    cursor_result = await db.execute(stmt)
    await db.commit()

    updated = int(getattr(cursor_result, "rowcount", 0))
    failed = len(body.finding_ids) - updated

    return BulkStatusResponse(updated=updated, failed=failed)
