"""Port for delivering findings to external notification destinations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ziran.domain.entities.alerting import AlertableFinding, DeliveryResult


class AlertSink(ABC):
    """Abstract port: delivers one finding to one external destination.

    Implementations (Slack webhook, GitHub issue, ...) live in infrastructure.

    Contract:
    - The ``github_issue`` sink MUST be idempotent: re-emitting a finding whose
      fingerprint already exists (open *or* closed issue) returns
      ``status="deduped"`` without creating a duplicate.
    - ``emit`` MUST NOT raise on remote/transport errors; capture them as
      ``DeliveryResult(status="failed", detail=...)``. Programmer errors MAY raise.
    - ``emit`` MUST NOT perform network I/O when wrapped by the dry-run decorator.
    """

    name: str

    @abstractmethod
    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        """Deliver one finding to this destination."""
        raise NotImplementedError
