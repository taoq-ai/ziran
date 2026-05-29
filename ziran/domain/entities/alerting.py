"""Alerting domain entities.

Normalized finding shape consumed by every :class:`~ziran.domain.ports.alert_sink.AlertSink`,
plus the per-delivery and per-run result aggregates and the pure fingerprint
helpers used for stateless deduplication.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ziran.domain.entities.attack import Severity

AlertKind = Literal["registry_drift", "dangerous_chain"]
DeliveryStatus = Literal["sent", "deduped", "skipped_below_floor", "failed", "dry_run"]
SinkKind = Literal["slack", "github_issue"]

# Canonical severity ordering (shared with policy export).
SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_rank(severity: Severity) -> int:
    """Return the numeric rank of *severity* for floor comparisons."""
    return SEVERITY_RANK[severity]


def _digest16(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def drift_fingerprint(server: str, tool: str, drift_type: str) -> str:
    """Fingerprint a registry drift finding by ``(server, tool, drift-kind)``.

    Deliberately excludes the changed value so a recurring drift of the same
    kind on the same tool reuses one issue.
    """
    return _digest16(f"drift|{server}|{tool}|{drift_type}")


def trace_fingerprint(tool_chain_hash: str, session_id: str) -> str:
    """Fingerprint a dangerous-chain trace finding by chain identity + session."""
    return _digest16(f"trace|{tool_chain_hash}|{session_id}")


def digest_fingerprint(chain_fingerprints: list[str]) -> str:
    """Fingerprint a trace digest from the sorted set of contained chain fingerprints.

    The run date is intentionally excluded so re-running on unchanged traces —
    even on a later day — reuses the same digest issue rather than filing a duplicate.
    """
    joined = "|".join(sorted(set(chain_fingerprints)))
    return _digest16(f"trace-digest|{joined}")


class AlertLink(BaseModel):
    """A labeled, remote-resolvable link attached to a finding."""

    label: str
    url: str


class AlertableFinding(BaseModel):
    """A normalized unit of information eligible for delivery to a sink."""

    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    kind: AlertKind
    severity: Severity
    title: str
    summary: str
    fields: dict[str, str] = Field(default_factory=dict)
    links: list[AlertLink] = Field(default_factory=list)
    remediation: str | None = None


class DeliveryResult(BaseModel):
    """Outcome of delivering one finding to one sink."""

    model_config = {"frozen": True}

    sink_name: str
    fingerprint: str
    status: DeliveryStatus
    detail: str | None = None


class AlertOutcome(BaseModel):
    """Aggregate of every per-(finding, sink) delivery in a single run."""

    results: list[DeliveryResult] = Field(default_factory=list)

    @property
    def any_failed(self) -> bool:
        return any(r.status == "failed" for r in self.results)

    @property
    def sent(self) -> int:
        return sum(1 for r in self.results if r.status == "sent")

    @property
    def deduped(self) -> int:
        return sum(1 for r in self.results if r.status == "deduped")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "failed")


class AlertSinkConfig(BaseModel):
    """Configuration for a single notification destination (from the ``alerts:`` block)."""

    kind: SinkKind
    severity_floor: Severity = "low"

    # slack
    webhook_url: str | None = None

    # github_issue
    repo: str | None = None
    token: str | None = None
    labels: list[str] = Field(default_factory=list)
    assignees: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_required(self) -> AlertSinkConfig:
        if self.kind == "slack" and not self.webhook_url:
            raise ValueError("slack alert sink requires 'webhook_url'")
        if self.kind == "github_issue" and not self.repo:
            raise ValueError("github_issue alert sink requires 'repo' (owner/name)")
        return self


class AlertConfig(BaseModel):
    """The ``alerts:`` block: a list of sink configurations."""

    alerts: list[AlertSinkConfig] = Field(default_factory=list)
