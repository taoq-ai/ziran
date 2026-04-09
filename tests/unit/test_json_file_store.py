"""Unit tests for JsonFileStore."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ziran.domain.entities.registry import ManifestSnapshot, ToolDescriptor
from ziran.infrastructure.snapshot_stores.json_file_store import JsonFileStore


def _make_snapshot(server_name: str = "test-server") -> ManifestSnapshot:
    return ManifestSnapshot(
        server_name=server_name,
        fetched_at=datetime(2025, 1, 1, tzinfo=UTC),
        tools=[
            ToolDescriptor(name="tool_a", description="Tool A"),
            ToolDescriptor(name="tool_b", description="Tool B", parameters={"type": "object"}),
        ],
        resources=[{"uri": "file:///data", "name": "data"}],
        prompts=[{"name": "summary"}],
    )


@pytest.mark.unit
class TestJsonFileStore:
    """Tests for the JSON file snapshot store."""

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        """A saved snapshot should be loadable with identical data."""
        store = JsonFileStore(tmp_path / "snapshots")
        snapshot = _make_snapshot()

        store.save("test-server", snapshot)
        loaded = store.load("test-server")

        assert loaded is not None
        assert loaded.server_name == snapshot.server_name
        assert loaded.fetched_at == snapshot.fetched_at
        assert len(loaded.tools) == 2
        assert loaded.tools[0].name == "tool_a"
        assert loaded.resources == snapshot.resources
        assert loaded.prompts == snapshot.prompts

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        """Loading a non-existent snapshot should return None."""
        store = JsonFileStore(tmp_path / "snapshots")
        assert store.load("nonexistent") is None

    def test_file_exists_after_save(self, tmp_path: Path) -> None:
        """Verify the JSON file exists on disk after save (atomic write)."""
        store = JsonFileStore(tmp_path / "snapshots")
        store.save("my-server", _make_snapshot("my-server"))

        expected_path = tmp_path / "snapshots" / "my-server.json"
        assert expected_path.exists()
        assert expected_path.stat().st_size > 0

    def test_overwrite_preserves_latest(self, tmp_path: Path) -> None:
        """Saving twice should overwrite with the latest snapshot."""
        store = JsonFileStore(tmp_path / "snapshots")
        snap1 = _make_snapshot()
        snap2 = ManifestSnapshot(
            server_name="test-server",
            fetched_at=datetime(2025, 6, 1, tzinfo=UTC),
            tools=[ToolDescriptor(name="new_tool", description="Updated")],
        )

        store.save("test-server", snap1)
        store.save("test-server", snap2)
        loaded = store.load("test-server")

        assert loaded is not None
        assert loaded.fetched_at == snap2.fetched_at
        assert len(loaded.tools) == 1
        assert loaded.tools[0].name == "new_tool"

    def test_creates_directory_if_missing(self, tmp_path: Path) -> None:
        """The store should create the snapshot directory if it doesn't exist."""
        deep_path = tmp_path / "a" / "b" / "c" / "snapshots"
        store = JsonFileStore(deep_path)
        store.save("srv", _make_snapshot("srv"))

        assert (deep_path / "srv.json").exists()

    def test_corrupt_file_returns_none(self, tmp_path: Path) -> None:
        """A corrupt JSON file should be treated as missing."""
        store = JsonFileStore(tmp_path / "snapshots")
        # Write garbage
        corrupt_path = tmp_path / "snapshots" / "corrupt.json"
        corrupt_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt_path.write_text("this is not json", encoding="utf-8")

        assert store.load("corrupt") is None
