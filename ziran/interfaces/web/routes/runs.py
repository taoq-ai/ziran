"""Runs CRUD + background scan execution."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from ziran.interfaces.web.dependencies import get_db, get_run_manager
from ziran.interfaces.web.models import Run
from ziran.interfaces.web.schemas import (
    RunCreate,
    RunDetail,
    RunListResponse,
    RunSummary,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from ziran.interfaces.web.services.run_manager import RunManager

router = APIRouter()


@router.get("/runs", response_model=RunListResponse)
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> RunListResponse:
    """List runs with optional filtering and pagination."""
    query = select(Run).order_by(Run.created_at.desc())
    count_query = select(func.count()).select_from(Run)

    if status:
        query = query.where(Run.status == status)
        count_query = count_query.where(Run.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    runs = result.scalars().all()

    return RunListResponse(
        items=[RunSummary.model_validate(r) for r in runs],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RunDetail:
    """Get full run detail including phase results."""
    result = await db.execute(
        select(Run).where(Run.id == run_id).options(selectinload(Run.phase_results))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunDetail.model_validate(run)


@router.post("/runs", response_model=RunSummary, status_code=201)
async def create_run(
    body: RunCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    manager: Annotated[RunManager, Depends(get_run_manager)],
) -> RunSummary:
    """Create a new run and start scanning in the background."""
    run = Run(
        id=uuid.uuid4(),
        name=body.name,
        target_agent=body.target_url,
        status="pending",
        coverage_level=body.coverage_level,
        strategy=body.strategy,
        config_json=body.model_dump(),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Start scan in background
    await manager.start_run(
        str(run.id),
        body.model_dump(),
    )

    return RunSummary.model_validate(run)


@router.delete("/runs/{run_id}", status_code=204)
async def delete_run(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    manager: Annotated[RunManager, Depends(get_run_manager)],
) -> None:
    """Delete a run. Returns 409 if still active."""
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if manager.is_active(str(run_id)):
        raise HTTPException(status_code=409, detail="Run is still active — cancel it first")
    await db.delete(run)
    await db.commit()


@router.post("/runs/{run_id}/cancel", status_code=200)
async def cancel_run(
    run_id: uuid.UUID,
    manager: Annotated[RunManager, Depends(get_run_manager)],
) -> dict[str, str]:
    """Cancel a running scan."""
    cancelled = await manager.cancel_run(str(run_id))
    if not cancelled:
        raise HTTPException(status_code=404, detail="No active scan for this run")
    return {"status": "cancelled"}
