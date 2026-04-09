"""Registry watcher domain entities.

Models for MCP server registry monitoring, manifest snapshots,
drift detection, and typosquat findings.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs at runtime
from typing import Any

from pydantic import BaseModel, Field


class ToolDescriptor(BaseModel):
    """Description of a single MCP tool from a server manifest."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str] = Field(default_factory=list)


class ManifestSnapshot(BaseModel):
    """Point-in-time snapshot of an MCP server's manifest."""

    server_name: str
    fetched_at: datetime
    tools: list[ToolDescriptor] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    raw_manifest: dict[str, Any] = Field(default_factory=dict)


class DriftFinding(BaseModel):
    """A single drift or typosquat finding from registry comparison."""

    server_name: str
    drift_type: str  # tool_added, tool_removed, description_changed, schema_changed, permission_changed, typosquat
    severity: str  # critical, high, medium, low
    tool_name: str | None = None
    field: str | None = None
    previous_value: str | None = None
    current_value: str | None = None
    suspected_canonical: str | None = None
    message: str


class ServerEntry(BaseModel):
    """Configuration entry for an MCP server to monitor."""

    name: str
    url: str
    transport: str = "streamable-http"  # stdio, sse, streamable-http


class RegistryConfig(BaseModel):
    """Configuration for the registry watcher."""

    servers: list[ServerEntry] = Field(default_factory=list)
    allowlist: list[str] = Field(default_factory=list)
    exemptions: list[str] = Field(default_factory=list)
    snapshot_dir: str | None = None
