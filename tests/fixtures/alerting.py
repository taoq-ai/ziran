"""Shared builders for alerting tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.domain.entities.alerting import AlertableFinding, AlertLink

if TYPE_CHECKING:
    from ziran.domain.entities.attack import Severity


def make_finding(
    *,
    fingerprint: str = "abcdef0123456789",
    severity: Severity = "high",
    kind: str = "registry_drift",
    remediation: str | None = None,
) -> AlertableFinding:
    """Build a representative finding for sink/dispatch tests."""
    return AlertableFinding(
        fingerprint=fingerprint,
        kind=kind,  # type: ignore[arg-type]
        severity=severity,
        title="Permission escalation on tool write_file (prod-mcp-server)",
        summary="Tool 'write_file' permissions changed on server 'prod-mcp-server'",
        fields={"Server": "prod-mcp-server", "Tool": "write_file", "Drift": "permission_changed"},
        links=[AlertLink(label="Snapshot diff", url="https://ci.example.com/snap/123")],
        remediation=remediation,
    )
