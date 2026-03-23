"""Pydantic request/response schemas for the web UI API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from ziran import __version__

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

# ── Health ─────────────────────────────────────────────────────────────


class HealthResponse(BaseModel):
    """Response for GET /api/health."""

    status: str
    version: str = __version__
    database: str


# ── Runs ───────────────────────────────────────────────────────────────


class RunCreate(BaseModel):
    """Request body for POST /api/runs."""

    target_url: str
    protocol: str | None = None
    coverage_level: str = "standard"
    phases: list[str] | None = None
    strategy: str = "fixed"
    concurrency: int = 5
    encoding: list[str] | None = None
    name: str | None = None


class RunSummary(BaseModel):
    """List-item response for GET /api/runs."""

    id: uuid.UUID
    name: str | None
    target_agent: str
    status: str
    coverage_level: str
    strategy: str
    total_vulnerabilities: int
    critical_paths_count: int
    dangerous_chains_count: int
    final_trust_score: float | None
    total_tokens: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class PhaseResultSchema(BaseModel):
    """Phase result nested in RunDetail."""

    id: uuid.UUID
    phase: str
    phase_index: int
    success: bool
    trust_score: float
    duration_seconds: float
    token_usage_json: dict[str, Any]
    vulnerabilities_found: list[Any]
    discovered_capabilities: list[Any]
    error: str | None

    model_config = {"from_attributes": True}


class RunDetail(RunSummary):
    """Full detail response for GET /api/runs/{run_id}."""

    config_json: dict[str, Any]
    result_json: dict[str, Any] | None
    graph_state_json: dict[str, Any] | None
    error: str | None
    phase_results: list[PhaseResultSchema] = Field(default_factory=list)


class RunListResponse(BaseModel):
    """Paginated wrapper for GET /api/runs."""

    items: list[RunSummary]
    total: int
    limit: int
    offset: int


# ── Progress (WebSocket) ──────────────────────────────────────────────


class ProgressMessage(BaseModel):
    """WebSocket progress event broadcast to subscribers."""

    event: str
    phase: str | None = None
    phase_index: int = 0
    total_phases: int = 0
    attack_index: int = 0
    total_attacks: int = 0
    attack_name: str = ""
    message: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
