"""Registry watcher application service.

Fetches MCP server manifests, diffs against stored snapshots,
and runs typosquat detection.  The ``ManifestFetcher`` protocol
allows dependency injection for testing.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from ziran.application.registry_watch.typosquat_detector import detect as detect_typosquat
from ziran.domain.entities.registry import (
    DriftFinding,
    ManifestSnapshot,
    RegistryConfig,
    ServerEntry,
    ToolDescriptor,
)

if TYPE_CHECKING:
    from ziran.domain.ports.snapshot_store import SnapshotStore

logger = logging.getLogger(__name__)


class ManifestFetcher(Protocol):
    """Protocol for fetching a server's manifest."""

    async def fetch(self, server: ServerEntry) -> dict[str, Any]: ...


# ──────────────────────────────────────────────────────────────────────
# Diff helpers
# ──────────────────────────────────────────────────────────────────────


def _tools_by_name(tools: list[ToolDescriptor]) -> dict[str, ToolDescriptor]:
    return {t.name: t for t in tools}


def _diff_manifests(
    server_name: str,
    old: ManifestSnapshot,
    new: ManifestSnapshot,
) -> list[DriftFinding]:
    """Compare two snapshots and return drift findings."""
    findings: list[DriftFinding] = []
    old_tools = _tools_by_name(old.tools)
    new_tools = _tools_by_name(new.tools)

    # Added tools
    for name in sorted(set(new_tools) - set(old_tools)):
        findings.append(
            DriftFinding(
                server_name=server_name,
                drift_type="tool_added",
                severity="medium",
                tool_name=name,
                current_value=new_tools[name].description,
                message=f"New tool '{name}' added to server '{server_name}'",
            )
        )

    # Removed tools
    for name in sorted(set(old_tools) - set(new_tools)):
        findings.append(
            DriftFinding(
                server_name=server_name,
                drift_type="tool_removed",
                severity="low",
                tool_name=name,
                previous_value=old_tools[name].description,
                message=f"Tool '{name}' removed from server '{server_name}'",
            )
        )

    # Changed tools
    for name in sorted(set(old_tools) & set(new_tools)):
        old_tool = old_tools[name]
        new_tool = new_tools[name]

        if old_tool.description != new_tool.description:
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    drift_type="description_changed",
                    severity="high",
                    tool_name=name,
                    field="description",
                    previous_value=old_tool.description,
                    current_value=new_tool.description,
                    message=f"Tool '{name}' description changed on server '{server_name}'",
                )
            )

        if old_tool.parameters != new_tool.parameters:
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    drift_type="schema_changed",
                    severity="medium",
                    tool_name=name,
                    field="parameters",
                    previous_value=str(old_tool.parameters),
                    current_value=str(new_tool.parameters),
                    message=f"Tool '{name}' input schema changed on server '{server_name}'",
                )
            )

        if old_tool.permissions != new_tool.permissions:
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    drift_type="permission_changed",
                    severity="high",
                    tool_name=name,
                    field="permissions",
                    previous_value=str(old_tool.permissions),
                    current_value=str(new_tool.permissions),
                    message=f"Tool '{name}' permissions changed on server '{server_name}'",
                )
            )

    return findings


def _raw_to_snapshot(server_name: str, raw: dict[str, Any]) -> ManifestSnapshot:
    """Convert a raw manifest dict into a ``ManifestSnapshot``."""
    tools: list[ToolDescriptor] = []
    for t in raw.get("tools", []):
        tools.append(
            ToolDescriptor(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                parameters=t.get("inputSchema", {}),
                permissions=t.get("permissions", []),
            )
        )

    return ManifestSnapshot(
        server_name=server_name,
        fetched_at=datetime.now(tz=UTC),
        tools=tools,
        resources=raw.get("resources", []),
        prompts=raw.get("prompts", []),
        raw_manifest=raw,
    )


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


async def watch(
    config: RegistryConfig,
    snapshot_store: SnapshotStore,
    fetcher: ManifestFetcher,
) -> list[DriftFinding]:
    """Run a single watch cycle across all configured servers.

    For each server the service:
    1. Fetches the current manifest via *fetcher*.
    2. Loads the previously stored snapshot.
    3. Diffs the two manifests to detect drift.
    4. Runs typosquat detection against the allowlist.
    5. Saves the new snapshot (only on success).

    Network errors are logged but do **not** corrupt stored snapshots.
    """
    all_findings: list[DriftFinding] = []

    for server in config.servers:
        try:
            raw = await fetcher.fetch(server)
        except Exception:
            logger.warning("Failed to fetch manifest for '%s' — skipping", server.name)
            continue

        new_snapshot = _raw_to_snapshot(server.name, raw)
        old_snapshot = snapshot_store.load(server.name)

        if old_snapshot is not None:
            drift = _diff_manifests(server.name, old_snapshot, new_snapshot)
            all_findings.extend(drift)

        # Typosquat detection
        typo_findings = detect_typosquat(server.name, config.allowlist, config.exemptions)
        all_findings.extend(typo_findings)

        # Also check tool names for typosquats
        for tool in new_snapshot.tools:
            tool_typo = detect_typosquat(tool.name, config.allowlist, config.exemptions)
            for f in tool_typo:
                f.tool_name = tool.name
            all_findings.extend(tool_typo)

        # Save new snapshot only after successful fetch
        snapshot_store.save(server.name, new_snapshot)

    return all_findings
