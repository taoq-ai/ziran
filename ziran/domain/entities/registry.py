"""Registry watcher domain entities.

Models for MCP server registry monitoring, manifest snapshots,
drift detection, and typosquat findings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, Field, SecretStr, model_validator

from ziran.domain.entities.alerting import (
    AlertableFinding,
    AlertSinkConfig,
    drift_fingerprint,
)
from ziran.domain.entities.attack import Severity


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
    drift_type: str  # tool_added, tool_removed, description_changed, schema_changed, permission_changed, typosquat, tool_poisoning
    severity: Severity
    tool_name: str | None = None
    field: str | None = None
    previous_value: str | None = None
    current_value: str | None = None
    suspected_canonical: str | None = None
    message: str

    def fingerprint(self) -> str:
        """Stable dedup key: ``(server, tool, drift-kind)``."""
        return drift_fingerprint(self.server_name, self.tool_name or "", self.drift_type)

    def to_alertable(self) -> AlertableFinding:
        """Map this drift finding to the normalized alerting shape.

        Before/after values are emitted as inline fields (the snapshot diff
        summary), since registry snapshots are local and have no remote URL.
        """
        fields: dict[str, str] = {
            "Server": self.server_name,
            "Drift type": self.drift_type,
        }
        if self.tool_name:
            fields["Tool"] = self.tool_name
        if self.field:
            fields["Field"] = self.field
        if self.previous_value is not None:
            fields["Previous"] = self.previous_value
        if self.current_value is not None:
            fields["Current"] = self.current_value
        if self.suspected_canonical:
            fields["Suspected canonical"] = self.suspected_canonical

        tool_suffix = f" on tool '{self.tool_name}'" if self.tool_name else ""
        return AlertableFinding(
            fingerprint=self.fingerprint(),
            kind="registry_drift",
            severity=self.severity,
            title=f"{self.drift_type}{tool_suffix} ({self.server_name})",
            summary=self.message,
            fields=fields,
        )


class ServerEntry(BaseModel):
    """Configuration entry for an MCP server to monitor.

    ``env`` and ``headers`` carry connection secrets: they are excluded from
    every serialisation and masked in ``repr`` so they never reach snapshots,
    reports or logs.
    """

    name: str
    url: str | None = None
    transport: str = "streamable-http"  # stdio, sse, streamable-http
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, SecretStr] = Field(default_factory=dict, exclude=True, repr=False)
    headers: dict[str, SecretStr] = Field(default_factory=dict, exclude=True, repr=False)

    @model_validator(mode="after")
    def _require_endpoint(self) -> Self:
        if self.url is None and self.command is None:
            raise ValueError("server requires 'url' or 'command'")
        return self


class RegistryConfig(BaseModel):
    """Configuration for the registry watcher."""

    servers: list[ServerEntry] = Field(default_factory=list)
    allowlist: list[str] = Field(default_factory=list)
    exemptions: list[str] = Field(default_factory=list)
    snapshot_dir: str | None = None
    alerts: list[AlertSinkConfig] = Field(default_factory=list)
