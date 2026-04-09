"""JSON file-based snapshot store.

Persists ``ManifestSnapshot`` objects as JSON files in a local
directory (default: ``.ziran/snapshots/``).  Writes are atomic
(temp file + rename) so a crash mid-write never corrupts the
stored snapshot.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from ziran.domain.entities.registry import ManifestSnapshot
from ziran.domain.ports.snapshot_store import SnapshotStore

logger = logging.getLogger(__name__)


class JsonFileStore(SnapshotStore):
    """Store snapshots as JSON files on the local filesystem."""

    def __init__(self, base_dir: Path | str) -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, server_name: str) -> Path:
        """Return the file path for a given server's snapshot."""
        safe_name = server_name.replace("/", "_").replace("\\", "_")
        return self._base_dir / f"{safe_name}.json"

    def load(self, server_name: str) -> ManifestSnapshot | None:
        """Load a snapshot from disk, or return ``None`` if absent."""
        path = self._path_for(server_name)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ManifestSnapshot.model_validate(data)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Corrupt snapshot file %s — treating as missing", path)
            return None

    def save(self, server_name: str, snapshot: ManifestSnapshot) -> None:
        """Atomically write a snapshot to disk."""
        path = self._path_for(server_name)
        content = snapshot.model_dump_json(indent=2)

        # Write to temp file in the same directory, then rename for atomicity
        fd, tmp_path = tempfile.mkstemp(dir=self._base_dir, suffix=".tmp", prefix=".snapshot-")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(content)
            Path(tmp_path).replace(path)
        except BaseException:
            # Clean up temp file on failure
            Path(tmp_path).unlink(missing_ok=True)
            raise
