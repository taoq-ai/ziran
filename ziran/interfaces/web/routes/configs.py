"""Config presets CRUD endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import ConfigPreset
from ziran.interfaces.web.schemas import (
    ConfigPresetCreate,
    ConfigPresetResponse,
    ConfigPresetUpdate,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


@router.get("/configs", response_model=list[ConfigPresetResponse])
async def list_configs(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ConfigPresetResponse]:
    """List all config presets ordered by creation date (newest first)."""
    result = await db.execute(select(ConfigPreset).order_by(ConfigPreset.created_at.desc()))
    presets = result.scalars().all()
    return [ConfigPresetResponse.model_validate(p) for p in presets]


@router.post("/configs", response_model=ConfigPresetResponse, status_code=201)
async def create_config(
    body: ConfigPresetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConfigPresetResponse:
    """Create a new config preset."""
    # Check name uniqueness
    existing = await db.execute(select(ConfigPreset).where(ConfigPreset.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Config preset name already exists")

    preset = ConfigPreset(
        name=body.name,
        description=body.description,
        config_json=body.config,
    )
    db.add(preset)
    await db.commit()
    await db.refresh(preset)
    return ConfigPresetResponse.model_validate(preset)


@router.put("/configs/{preset_id}", response_model=ConfigPresetResponse)
async def update_config(
    preset_id: uuid.UUID,
    body: ConfigPresetUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConfigPresetResponse:
    """Update an existing config preset (partial update)."""
    preset = await db.get(ConfigPreset, preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Config preset not found")

    update_data = body.model_dump(exclude_unset=True)

    # Map 'config' field to 'config_json' column
    if "config" in update_data:
        preset.config_json = update_data.pop("config")
    if "name" in update_data:
        preset.name = update_data["name"]
    if "description" in update_data:
        preset.description = update_data["description"]

    preset.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(preset)
    return ConfigPresetResponse.model_validate(preset)


@router.delete("/configs/{preset_id}", status_code=204)
async def delete_config(
    preset_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Delete a config preset."""
    preset = await db.get(ConfigPreset, preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Config preset not found")

    await db.delete(preset)
    await db.commit()
