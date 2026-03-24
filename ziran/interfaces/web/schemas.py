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


# ── Findings ──────────────────────────────────────────────────────────


class FindingSummary(BaseModel):
    """List-item response for GET /api/findings."""

    id: uuid.UUID
    run_id: uuid.UUID
    vector_name: str
    category: str
    severity: str
    owasp_category: str | None
    target_agent: str
    status: str
    title: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ComplianceMappingSchema(BaseModel):
    """Compliance mapping nested in FindingDetail."""

    framework: str
    control_id: str
    control_name: str

    model_config = {"from_attributes": True}


class FindingDetail(FindingSummary):
    """Full detail response for GET /api/findings/{id}."""

    fingerprint: str
    vector_id: str
    status_changed_at: datetime | None
    description: str | None
    remediation: str | None
    prompt_used: str | None
    agent_response: str | None
    evidence: dict[str, Any] | None
    detection_metadata: dict[str, Any] | None
    business_impact: list[Any] | None
    compliance_mappings: list[ComplianceMappingSchema] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    """Request body for PATCH /api/findings/{id}/status."""

    status: str


class BulkStatusUpdate(BaseModel):
    """Request body for POST /api/findings/bulk-status."""

    finding_ids: list[uuid.UUID]
    status: str


class BulkStatusResponse(BaseModel):
    """Response for POST /api/findings/bulk-status."""

    updated: int
    failed: int


class FindingListResponse(BaseModel):
    """Paginated wrapper for GET /api/findings."""

    items: list[FindingSummary]
    total: int
    limit: int
    offset: int


class FindingStats(BaseModel):
    """Aggregate finding statistics."""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_category: dict[str, int]
    by_owasp: dict[str, int]


# ── Compliance ────────────────────────────────────────────────────────


class OwaspCategoryStatus(BaseModel):
    """Single OWASP category in compliance matrix."""

    control_id: str
    control_name: str
    description: str
    finding_count: int
    by_severity: dict[str, int]
    status: str  # critical, warning, pass, not_tested


class ComplianceSummary(BaseModel):
    """Summary section of OWASP compliance response."""

    total_categories: int
    tested: int
    not_tested: int
    with_critical: int
    with_findings: int


class OwaspComplianceResponse(BaseModel):
    """Response for GET /api/compliance/owasp."""

    categories: list[OwaspCategoryStatus]
    summary: ComplianceSummary
