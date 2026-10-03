"""Port for text-embedding providers (spec 042)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class BaseEmbedder(ABC):
    """Port for text-embedding providers (spec 042)."""

    @abstractmethod
    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one vector per text, in input order. Raise on any provider failure."""
