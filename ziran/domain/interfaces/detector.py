"""Abstract detector interface for the multi-detector pipeline.

All detectors must implement BaseDetector. The pipeline runs
each detector against an agent response and resolves conflicts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ziran.domain.entities.attack import AttackPrompt, AttackVector
    from ziran.domain.entities.detection import DetectorResult
    from ziran.domain.interfaces.adapter import AgentResponse


class BaseDetector(ABC):
    """Abstract base for all attack-success detectors.

    Detectors evaluate a single prompt/response pair and return a
    :class:`~koan.domain.entities.detection.DetectorResult` with a
    score between 0.0 (safe) and 1.0 (attack succeeded).

    The pipeline calls detectors in priority order and uses a
    "refusal always wins" conflict-resolution strategy.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this detector (e.g. ``'refusal'``)."""

    @abstractmethod
    def detect(
        self,
        prompt: str,
        response: AgentResponse,
        prompt_spec: AttackPrompt,
        vector: AttackVector | None = None,
    ) -> DetectorResult:
        """Evaluate whether an attack succeeded.

        Args:
            prompt: The rendered prompt that was sent to the agent.
            response: The agent's response.
            prompt_spec: The prompt specification with indicator patterns.
            vector: The full attack vector (optional, for context).

        Returns:
            Detection result with score, confidence, and reasoning.
        """
