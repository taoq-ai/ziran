"""Port for persisting and loading MCP manifest snapshots."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ziran.domain.entities.registry import ManifestSnapshot


class SnapshotStore(ABC):
    """Abstract port for snapshot storage.

    Implementations may store snapshots as local JSON files,
    in a database, or in object storage.
    """

    @abstractmethod
    def load(self, server_name: str) -> ManifestSnapshot | None:
        """Load the most recent snapshot for a server.

        Returns ``None`` if no snapshot exists.
        """
        ...

    @abstractmethod
    def save(self, server_name: str, snapshot: ManifestSnapshot) -> None:
        """Persist a snapshot, overwriting any previous version."""
        ...
