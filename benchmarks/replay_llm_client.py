"""Offline LLM client that replays recorded llm_judge verdicts (spec 021).

The detection-accuracy benchmark must be deterministic and run in CI with no
network access. Each :class:`DetectionExample` stores the judge's verdict it
was recorded with; this client returns that verdict instead of calling a live
model, so ``DetectorPipeline`` exercises its real llm_judge branch offline.

The pipeline's judge embeds the agent's response verbatim in the user message
it sends to the model, so we key replay on the recorded ``response_text``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

if TYPE_CHECKING:
    from benchmarks.ground_truth.schema import DetectionExample, RecordedJudgeVerdict


#: Returned when the judge is invoked on an example with no recorded verdict.
#: confidence 0.0 keeps it below the pipeline's llm_judge confidence gate, so
#: the pipeline ignores it — correct, because the schema already requires a
#: recorded verdict for any example that expects the llm_judge detector.
_IGNORED_VERDICT = {"verdict": "ambiguous", "confidence": 0.0, "reasoning": "no recorded verdict"}


class ReplayLLMClient(BaseLLMClient):
    """Returns recorded llm_judge verdicts keyed by recorded response text."""

    def __init__(self, examples: list[DetectionExample]) -> None:
        super().__init__(LLMConfig(provider="replay", model="replay"))
        # Map recorded response text → its judge verdict (only examples that
        # actually carry one). Later duplicates overwrite earlier ones.
        self._by_response: dict[str, RecordedJudgeVerdict] = {
            ex.response_text: ex.recorded_judge for ex in examples if ex.recorded_judge is not None
        }

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        user_message = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
        )
        verdict = self._lookup(user_message)
        if verdict is None:
            # The pipeline runs the judge on every example; one whose response
            # has no recorded verdict simply doesn't exercise the judge branch.
            return LLMResponse(content=json.dumps(_IGNORED_VERDICT), model="replay")
        payload = {
            "verdict": verdict.label,
            "confidence": verdict.confidence,
            "reasoning": verdict.rationale,
        }
        return LLMResponse(content=json.dumps(payload), model="replay")

    async def health_check(self) -> bool:
        return True

    def _lookup(self, user_message: str) -> RecordedJudgeVerdict | None:
        # The pipeline formats the user message as
        # "...AGENT RESPONSE:\n{text}\n\nATTACK OBJECTIVE:...". Parse the response
        # text out and do an exact dict lookup so that one example's response being
        # a substring of another's can't return the wrong verdict.
        exact = self._extract_response(user_message)
        if exact is not None and exact in self._by_response:
            return self._by_response[exact]
        # Fallback: substring scan (e.g. if the prompt format ever changes).
        for response_text, verdict in self._by_response.items():
            if response_text in user_message:
                return verdict
        return None

    @staticmethod
    def _extract_response(user_message: str) -> str | None:
        marker, end = "AGENT RESPONSE:\n", "\n\nATTACK OBJECTIVE:"
        start = user_message.find(marker)
        if start == -1:
            return None
        start += len(marker)
        stop = user_message.find(end, start)
        return user_message[start:stop] if stop != -1 else user_message[start:]
