"""Multi-turn jailbreak tactics for progressive attack sequences.

Controls how multi-prompt attack vectors are executed against agents.
Instead of treating each prompt independently (single tactic), multi-turn
tactics send all prompts sequentially within the same conversation to
build context progressively.

Tactic types:
    - **single**: Each prompt independent, stop on first success (default).
    - **crescendo**: Gradually escalate from innocent to exploit.
    - **context_buildup**: Build conversational context before the payload.
    - **persona_shift**: Establish authority, then use it to bypass.
    - **distraction**: Alternate benign and malicious prompts.

Usage::

    executor = TacticExecutor(adapter)
    result = await executor.execute(attack, detector_pipeline, render_fn)
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING

from ziran.domain.entities.attack import AttackResult, TokenUsage

if TYPE_CHECKING:
    from collections.abc import Callable

    from ziran.application.detectors.pipeline import DetectorPipeline
    from ziran.domain.entities.attack import AttackPrompt, AttackVector
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = logging.getLogger(__name__)


class TacticType(StrEnum):
    """Execution tactics for multi-prompt attack vectors."""

    SINGLE = "single"
    CRESCENDO = "crescendo"
    CONTEXT_BUILDUP = "context_buildup"
    PERSONA_SHIFT = "persona_shift"
    DISTRACTION = "distraction"
    FEW_SHOT = "few_shot"
    REFUSAL_SUPPRESSION = "refusal_suppression"
    HYPOTHETICAL = "hypothetical"
    ROLE_PLAY = "role_play"
    LANGUAGE_SWITCH = "language_switch"
    CODE_MODE = "code_mode"


class TacticExecutor:
    """Executes multi-turn attack sequences against an agent.

    For multi-turn tactics, all prompts in the vector are sent
    sequentially within the same conversation (no ``reset_state()``
    between prompts). Detection is only evaluated on prompts that
    have ``success_indicators`` defined, since earlier prompts in
    the sequence are setup/context builders.

    Example::

        executor = TacticExecutor(adapter)
        result = await executor.execute(
            attack=vector,
            detector_pipeline=pipeline,
            render_fn=AgentScanner._render_prompt,
        )
    """

    def __init__(self, adapter: BaseAgentAdapter) -> None:
        self._adapter = adapter

    async def execute(
        self,
        attack: AttackVector,
        detector_pipeline: DetectorPipeline,
        render_fn: Callable[[AttackPrompt], str],
    ) -> AttackResult:
        """Execute a multi-turn attack sequence.

        All prompts are sent sequentially in the same conversation.
        Detection is evaluated only on prompts with success_indicators.
        Token usage is accumulated across all turns.

        Args:
            attack: The attack vector with tactic and prompts.
            detector_pipeline: Pipeline for evaluating responses.
            render_fn: Function to render prompt templates.

        Returns:
            Attack result from the multi-turn sequence.
        """
        if not attack.prompts:
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                error="No prompts defined for this attack vector",
                owasp_mapping=attack.owasp_mapping,
                atlas_mapping=attack.atlas_mapping,
                harm_category=attack.harm_category,
            )

        total_tokens = TokenUsage()
        last_response_content: str | None = None
        last_prompt_used: str | None = None

        for i, prompt_spec in enumerate(attack.prompts):
            rendered_prompt = render_fn(prompt_spec)

            try:
                response = await self._adapter.invoke(rendered_prompt)

                total_tokens = total_tokens + TokenUsage(
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )

                if response.content:
                    last_response_content = response.content
                    last_prompt_used = rendered_prompt

                # Only evaluate detection on prompts with success indicators
                # (earlier prompts are just setup/context building)
                if not prompt_spec.success_indicators:
                    logger.debug(
                        "Turn %d/%d for %s: context building (no indicators)",
                        i + 1,
                        len(attack.prompts),
                        attack.id,
                    )
                    continue

                verdict = await detector_pipeline.evaluate(
                    rendered_prompt,
                    response,
                    prompt_spec,
                    attack,
                )

                if verdict.successful:
                    from ziran.application.detectors.side_effect import (
                        get_side_effect_summary,
                    )

                    side_effects = get_side_effect_summary(response.tool_calls)
                    return AttackResult(
                        vector_id=attack.id,
                        vector_name=attack.name,
                        category=attack.category,
                        severity=attack.severity,
                        successful=True,
                        evidence={
                            "response_snippet": response.content[:500],
                            "tool_calls": response.tool_calls,
                            "matched_indicators": verdict.matched_indicators,
                            "detector_scores": {
                                r.detector_name: r.score for r in verdict.detector_results
                            },
                            "detector_reasoning": verdict.reasoning,
                            "side_effects": side_effects,
                            "tactic": attack.tactic,
                            "turn": i + 1,
                            "total_turns": len(attack.prompts),
                        },
                        agent_response=response.content,
                        prompt_used=rendered_prompt,
                        owasp_mapping=attack.owasp_mapping,
                        atlas_mapping=attack.atlas_mapping,
                        harm_category=attack.harm_category,
                        token_usage=total_tokens,
                    )

            except TimeoutError:
                logger.warning("Turn %d for %s timed out", i + 1, attack.id)
            except (ConnectionError, OSError) as exc:
                logger.warning(
                    "Connection error on turn %d for %s: %s",
                    i + 1,
                    attack.id,
                    exc,
                )
            except Exception as exc:
                logger.warning("Error on turn %d for %s: %s", i + 1, attack.id, exc)

        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            successful=False,
            evidence={
                "note": "Multi-turn sequence completed without success",
                "tactic": attack.tactic,
                "turns_attempted": len(attack.prompts),
            },
            agent_response=last_response_content,
            prompt_used=last_prompt_used,
            owasp_mapping=attack.owasp_mapping,
            atlas_mapping=attack.atlas_mapping,
            harm_category=attack.harm_category,
            token_usage=total_tokens,
        )
