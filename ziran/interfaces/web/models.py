"""SQLAlchemy ORM models for the web UI."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean as SaBool
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all web UI models."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Run(Base):
    """A single security scan execution."""

    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_agent: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    coverage_level: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")
    strategy: Mapped[str] = mapped_column(String(20), nullable=False, default="fixed")
    config_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_paths_count: Mapped[int] = mapped_column(Integer, default=0)
    dangerous_chains_count: Mapped[int] = mapped_column(Integer, default=0)
    final_trust_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)

    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    graph_state_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    phase_results: Mapped[list[PhaseResultRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_runs_status", "status"),
        Index("ix_runs_created_at", "created_at"),
    )


class PhaseResultRow(Base):
    """Outcome of a single phase within a run."""

    __tablename__ = "phase_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    phase_index: Mapped[int] = mapped_column(Integer, nullable=False)
    success: Mapped[bool] = mapped_column(SaBool, nullable=False)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    token_usage_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    vulnerabilities_found: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    discovered_capabilities: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    run: Mapped[Run] = relationship(back_populates="phase_results")

    __table_args__ = (Index("ix_phase_results_run_id", "run_id"),)


class ConfigPreset(Base):
    """A saved scan configuration preset."""

    __tablename__ = "config_presets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
