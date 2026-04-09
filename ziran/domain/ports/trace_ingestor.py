"""Port for ingesting production traces into TraceSession objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.trace import TraceSession


class TraceIngestor(ABC):
    """Port for ingesting production traces."""

    @abstractmethod
    async def ingest(self, source: Path | str, **kwargs: Any) -> list[TraceSession]: ...
