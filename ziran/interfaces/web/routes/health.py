"""Health check endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(db: Annotated[AsyncSession, Depends(get_db)]) -> HealthResponse:
    """Return service health including database connectivity."""
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
        status = "ok"
    except Exception:
        db_status = "disconnected"
        status = "degraded"

    return HealthResponse(status=status, database=db_status)
