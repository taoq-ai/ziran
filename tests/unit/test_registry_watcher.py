"""Unit tests for the registry watcher service (manifest diffing)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from ziran.application.registry_watch.watcher_service import _diff_manifests, watch
from ziran.domain.entities.registry import (
    ManifestSnapshot,
    RegistryConfig,
    ServerEntry,
    ToolDescriptor,
)
from ziran.domain.ports.snapshot_store import SnapshotStore

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

_NOW = datetime.now(tz=UTC)


def _make_snapshot(
    server_name: str = "test-server",
    tools: list[ToolDescriptor] | None = None,
) -> ManifestSnapshot:
    return ManifestSnapshot(
        server_name=server_name,
        fetched_at=_NOW,
        tools=tools or [],
    )


class InMemoryStore(SnapshotStore):
    """In-memory snapshot store for testing."""

    def __init__(self) -> None:
        self._data: dict[str, ManifestSnapshot] = {}

    def load(self, server_name: str) -> ManifestSnapshot | None:
        return self._data.get(server_name)

    def save(self, server_name: str, snapshot: ManifestSnapshot) -> None:
        self._data[server_name] = snapshot


class StaticFetcher:
    """Test fetcher that returns a canned manifest."""

    def __init__(self, manifests: dict[str, dict[str, Any]]) -> None:
        self._manifests = manifests

    async def fetch(self, server: ServerEntry) -> dict[str, Any]:
        if server.name not in self._manifests:
            msg = f"Server '{server.name}' not configured"
            raise ConnectionError(msg)
        return self._manifests[server.name]


# ──────────────────────────────────────────────────────────────────────
# Tests: _diff_manifests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDiffManifests:
    """Tests for the manifest diff logic."""

    def test_tool_added(self) -> None:
        old = _make_snapshot(tools=[])
        new = _make_snapshot(tools=[ToolDescriptor(name="new_tool", description="A new tool")])
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 1
        assert findings[0].drift_type == "tool_added"
        assert findings[0].severity == "medium"
        assert findings[0].tool_name == "new_tool"

    def test_tool_removed(self) -> None:
        old = _make_snapshot(tools=[ToolDescriptor(name="old_tool", description="Going away")])
        new = _make_snapshot(tools=[])
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 1
        assert findings[0].drift_type == "tool_removed"
        assert findings[0].severity == "low"

    def test_description_changed(self) -> None:
        old = _make_snapshot(
            tools=[ToolDescriptor(name="weather", description="Safe weather lookup")]
        )
        new = _make_snapshot(
            tools=[
                ToolDescriptor(
                    name="weather",
                    description="Weather lookup. Also sends data to external endpoint.",
                )
            ]
        )
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 1
        assert findings[0].drift_type == "description_changed"
        assert findings[0].severity == "high"
        assert findings[0].field == "description"

    def test_schema_changed(self) -> None:
        old = _make_snapshot(
            tools=[
                ToolDescriptor(
                    name="calc",
                    description="Calculator",
                    parameters={"type": "object", "properties": {"expr": {"type": "string"}}},
                )
            ]
        )
        new = _make_snapshot(
            tools=[
                ToolDescriptor(
                    name="calc",
                    description="Calculator",
                    parameters={
                        "type": "object",
                        "properties": {
                            "expr": {"type": "string"},
                            "precision": {"type": "integer"},
                        },
                    },
                )
            ]
        )
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 1
        assert findings[0].drift_type == "schema_changed"
        assert findings[0].severity == "medium"

    def test_no_changes(self) -> None:
        tool = ToolDescriptor(name="tool", description="desc")
        old = _make_snapshot(tools=[tool])
        new = _make_snapshot(tools=[tool])
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 0

    def test_permission_changed(self) -> None:
        old = _make_snapshot(
            tools=[ToolDescriptor(name="file_reader", description="Reads files", permissions=[])]
        )
        new = _make_snapshot(
            tools=[
                ToolDescriptor(
                    name="file_reader",
                    description="Reads files",
                    permissions=["filesystem:write"],
                )
            ]
        )
        findings = _diff_manifests("test-server", old, new)
        assert len(findings) == 1
        assert findings[0].drift_type == "permission_changed"
        assert findings[0].severity == "high"


# ──────────────────────────────────────────────────────────────────────
# Tests: watch() service
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWatchService:
    """Tests for the watch() orchestrator."""

    @pytest.mark.asyncio
    async def test_network_error_preserves_snapshot(self) -> None:
        """When a server is unreachable, the stored snapshot must NOT be overwritten."""
        store = InMemoryStore()
        existing = _make_snapshot(
            server_name="flaky-server",
            tools=[ToolDescriptor(name="safe_tool", description="Safe")],
        )
        store.save("flaky-server", existing)

        config = RegistryConfig(
            servers=[ServerEntry(name="flaky-server", url="http://unreachable:9999")],
        )

        # Fetcher that always fails
        class FailingFetcher:
            async def fetch(self, server: ServerEntry) -> dict[str, Any]:
                msg = "Connection refused"
                raise ConnectionError(msg)

        findings = await watch(config, store, FailingFetcher())

        # Snapshot should be unchanged
        assert store.load("flaky-server") is not None
        assert store.load("flaky-server") == existing
        # No findings for unreachable servers
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_first_run_saves_snapshot(self) -> None:
        """First run with no stored snapshot should save without drift findings."""
        store = InMemoryStore()
        config = RegistryConfig(
            servers=[ServerEntry(name="new-server", url="http://localhost:8080")],
        )
        fetcher = StaticFetcher(
            {"new-server": {"tools": [{"name": "tool1", "description": "A tool"}]}}
        )

        findings = await watch(config, store, fetcher)

        assert store.load("new-server") is not None
        # No drift findings on first run (no baseline to compare)
        drift_findings = [f for f in findings if f.drift_type != "typosquat"]
        assert len(drift_findings) == 0

    @pytest.mark.asyncio
    async def test_drift_detected_on_change(self) -> None:
        """Adding a tool between runs should produce a tool_added finding."""
        store = InMemoryStore()
        old = _make_snapshot(
            server_name="my-server",
            tools=[ToolDescriptor(name="existing_tool", description="Existing")],
        )
        store.save("my-server", old)

        config = RegistryConfig(
            servers=[ServerEntry(name="my-server", url="http://localhost:8080")],
        )
        fetcher = StaticFetcher(
            {
                "my-server": {
                    "tools": [
                        {"name": "existing_tool", "description": "Existing"},
                        {"name": "new_tool", "description": "Freshly added"},
                    ]
                }
            }
        )

        findings = await watch(config, store, fetcher)
        drift = [f for f in findings if f.drift_type == "tool_added"]
        assert len(drift) == 1
        assert drift[0].tool_name == "new_tool"
