"""Port for rendering DangerousChain findings into guardrail policies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ziran.domain.entities.capability import DangerousChain
    from ziran.domain.entities.policy import GuardrailPolicy, GuardrailPolicyFormat


class PolicyRenderer(ABC):
    """Port for rendering DangerousChain findings into guardrail policies."""

    @property
    @abstractmethod
    def format(self) -> GuardrailPolicyFormat:
        """The guardrail format this renderer produces."""
        ...

    @abstractmethod
    def render(
        self,
        finding: DangerousChain,
        finding_id: str,
    ) -> GuardrailPolicy:
        """Render a single finding into a guardrail policy."""
        ...
