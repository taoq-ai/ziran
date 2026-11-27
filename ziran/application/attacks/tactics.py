"""Multi-turn jailbreak tactics for progressive attack sequences.

Controls how multi-prompt attack vectors are executed against agents.
Instead of treating each prompt independently (single tactic), multi-turn
tactics send all prompts sequentially within the same conversation to
build context progressively. A prompt with ``new_session`` starts a new
conversation first (``reset_state()``), for memory that outlives a session.

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

import asyncio
import weakref
from collections import Counter
from contextlib import asynccontextmanager
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from ziran.application.detectors.ensemble import review_evidence
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.domain.interfaces.adapter import scan_metadata
from ziran.domain.replies import is_error_response, is_no_chat_reply
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from ziran.application.detectors.pipeline import DetectorPipeline
    from ziran.domain.entities.attack import AttackPrompt, AttackVector
    from ziran.domain.entities.goal import Replies, Turns
    from ziran.domain.interfaces.adapter import BaseAgentAdapter

logger = get_logger(__name__)

#: Why a two-session vector did not run against a target without memory across resets.
NO_MEMORY_REASON = "no memory across sessions"
#: Why a two-session result is unmeasured: the adapter's history holds turns it did not send.
SHARED_SESSION_REASON = "session 2 shared"
#: Why a two-session result is unmeasured: the plant (session 1) got no reply.
NO_PLANT_REASON = "session 1 got no reply"


class _SessionGate:
    """Per-adapter gate (spec 113): multi-turn runs share it, a two-session run holds it alone,
    so its reset never lands inside another run's conversation. A waiting two-session run blocks
    new shared holders, so it is not starved."""

    def __init__(self) -> None:
        self._cond = asyncio.Condition()
        self._shared = 0
        self._exclusive = False
        self._waiting = 0
        self._wakers: set[asyncio.Future[None]] = set()

    @asynccontextmanager
    async def hold(self, exclusive: bool) -> AsyncIterator[None]:
        async with self._cond:
            if exclusive:
                self._waiting += 1
                try:
                    await self._cond.wait_for(lambda: not self._exclusive and not self._shared)
                finally:
                    self._waiting -= 1
                    self._cond.notify_all()
                self._exclusive = True
            else:
                await self._cond.wait_for(lambda: not self._exclusive and not self._waiting)
                self._shared += 1
        try:
            yield
        finally:
            # Release first, with no await, so a cancel cannot leave the gate held; the wake-up
            # runs in its own task, so a second cancel cannot drop it either.
            if exclusive:
                self._exclusive = False
            else:
                self._shared -= 1
            wake = asyncio.ensure_future(self._wake())
            self._wakers.add(wake)
            wake.add_done_callback(self._wakers.discard)
            await asyncio.shield(wake)

    async def _wake(self) -> None:
        async with self._cond:
            self._cond.notify_all()


_GATES: weakref.WeakKeyDictionary[BaseAgentAdapter, _SessionGate] = weakref.WeakKeyDictionary()


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
    PAIR = "pair"  # attacker-LLM refinement, run by PairExecutor (spec 081)
    TAP = "tap"  # attacker-LLM tree search, run by CampaignExecutor (spec 128)
    CRESCENDO_LIVE = "crescendo_live"  # attacker-LLM conversation (spec 128)


class TacticExecutor:
    """Executes multi-turn attack sequences against an agent.

    For multi-turn tactics, all prompts in the vector are sent
    sequentially within the same conversation (no ``reset_state()``
    between prompts, except before a ``new_session`` prompt).
    Detection is only evaluated on prompts that have
    ``success_indicators`` defined, since earlier prompts in the
    sequence are setup/context builders.

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
        turns: Turns | None = None,
        replies: Replies | None = None,
    ) -> AttackResult:
        """Execute a multi-turn attack sequence.

        All prompts are sent sequentially in the same conversation.
        Detection is evaluated only on prompts with success_indicators.
        Token usage is accumulated across all turns.

        Args:
            attack: The attack vector with tactic and prompts.
            detector_pipeline: Pipeline for evaluating responses.
            render_fn: Function to render prompt templates.
            turns: Filled with each reply's tool calls by turn, for a side-effect goal.
            replies: Filled with each reply's text by turn, for a secret goal (spec 124).

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
                owasp_agentic_mapping=attack.owasp_agentic_mapping,
                atlas_mapping=attack.atlas_mapping,
                harm_category=attack.harm_category,
            )

        # Two-session memory vectors (spec 113): skip a target that forgets on reset, else one
        # record per session of what was sent, replied and called.
        two_session = any(p.new_session for p in attack.prompts)
        if two_session and not self._adapter.memory_persists_across_reset:
            logger.info("new_session_skipped", vector_id=attack.id, reason=NO_MEMORY_REASON)
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                evidence={"skipped": NO_MEMORY_REASON, "outcome": "unmeasured"},
                owasp_mapping=attack.owasp_mapping,
                owasp_agentic_mapping=attack.owasp_agentic_mapping,
                atlas_mapping=attack.atlas_mapping,
                harm_category=attack.harm_category,
            )
        log = ({} if turns is None else turns, {} if replies is None else replies)
        # Every run holds the gate (shared here): a TAP node's reset (spec 133) waits for it.
        gate = _GATES.setdefault(self._adapter, _SessionGate())
        async with gate.hold(exclusive=two_session):
            return await self._run(attack, detector_pipeline, render_fn, two_session, *log)

    def _shared(self, session: dict[str, Any]) -> bool:
        """True when the adapter's history holds a user or assistant message this session did
        not send or receive: another run's turn landed in it (spec 113)."""
        own: Counter[tuple[str | None, str | None]] = Counter(
            ("user", t["prompt"]) for t in session["turns"]
        )
        own += Counter(("assistant", t["reply"]) for t in session["turns"])
        history = self._adapter.get_state().conversation_history
        roles = ("user", "assistant")
        seen = Counter((m.get("role"), m.get("content")) for m in history if m.get("role") in roles)
        return bool(seen - own)  # counts, not membership: a stray copy of an own reply is foreign

    async def _run(
        self,
        attack: AttackVector,
        detector_pipeline: DetectorPipeline,
        render_fn: Callable[[AttackPrompt], str],
        two_session: bool,
        turns: Turns,
        replies: Replies,
    ) -> AttackResult:
        sessions: list[dict[str, Any]] = []  # one record per session, two-session vectors only
        unmeasured_reason: str | None = None

        total_tokens = TokenUsage()
        last_response_content: str | None = None
        last_prompt_used: str | None = None
        review: dict[str, Any] = {}
        prompt_errors = 0  # swallowed turn failures; non-zero blocks caching (spec 049)
        evaluated = 0  # turns that reached the detectors
        sent: list[str] = []  # every turn so far is the attack: a value may come from any

        for i, prompt_spec in enumerate(attack.prompts):
            rendered_prompt = render_fn(prompt_spec)
            if two_session:
                planted = (
                    any(t["reply"] is not None for t in sessions[-1]["turns"]) if sessions else True
                )
                if prompt_spec.new_session and not planted:
                    unmeasured_reason = NO_PLANT_REASON  # nothing planted: nothing to test
                    break
                if prompt_spec.new_session:
                    self._adapter.reset_state()
                if prompt_spec.new_session or not sessions:
                    sessions.append({"session": len(sessions) + 1, "turns": []})
                turn: dict[str, Any] = {"turn": i + 1, "prompt": rendered_prompt, "reply": None}
                sessions[-1]["turns"].append(turn)

            try:
                response = await self._adapter.invoke(rendered_prompt)
                if two_session:
                    turn.update(reply=response.content, tool_calls=response.tool_calls)
                    if len(sessions) > 1 and self._shared(sessions[-1]):
                        unmeasured_reason = SHARED_SESSION_REASON
                        logger.warning("new_session_shared", vector_id=attack.id, turn=i + 1)
                        break
                sent.append(rendered_prompt)
                response.metadata = scan_metadata(response.metadata, *sent)

                total_tokens = total_tokens + TokenUsage(
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )

                if is_no_chat_reply(response.content):  # no prompt reached the target (spec 082)
                    prompt_errors += 1
                    continue
                if not is_error_response(response.content):
                    turns[i + 1], replies[i + 1] = response.tool_calls, response.content

                if response.content:
                    last_response_content = response.content
                    last_prompt_used = rendered_prompt

                # Only evaluate detection on prompts with success indicators
                # (earlier prompts are just setup/context building)
                if not prompt_spec.success_indicators:
                    logger.debug(
                        "turn_context_building",
                        turn=i + 1,
                        total_turns=len(attack.prompts),
                        vector_id=attack.id,
                    )
                    continue

                verdict = await detector_pipeline.evaluate(
                    rendered_prompt,
                    response,
                    prompt_spec,
                    attack,
                )
                evaluated += 1
                if verdict.needs_review:
                    review = review_evidence(verdict)

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
                            **review_evidence(verdict),
                            **({"sessions": sessions} if two_session else {}),
                        },
                        agent_response=response.content,
                        prompt_used=rendered_prompt,
                        owasp_mapping=attack.owasp_mapping,
                        owasp_agentic_mapping=attack.owasp_agentic_mapping,
                        atlas_mapping=attack.atlas_mapping,
                        harm_category=attack.harm_category,
                        token_usage=total_tokens,
                    )

            except TimeoutError:
                prompt_errors += 1
                logger.warning("turn_timed_out", turn=i + 1, vector_id=attack.id)
            except (ConnectionError, OSError) as exc:
                prompt_errors += 1
                logger.warning(
                    "turn_connection_error",
                    turn=i + 1,
                    vector_id=attack.id,
                    error=str(exc),
                )
            except Exception as exc:
                prompt_errors += 1
                logger.warning("turn_error", turn=i + 1, vector_id=attack.id, error=str(exc))

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
                **review,
                **({"prompt_errors": prompt_errors} if prompt_errors else {}),
                **({"outcome": "unmeasured"} if prompt_errors and not evaluated else {}),
                **(
                    {"outcome": "unmeasured", "unmeasured_reason": unmeasured_reason}
                    if unmeasured_reason
                    else {}
                ),
                **({"sessions": sessions} if two_session else {}),
            },
            agent_response=last_response_content,
            prompt_used=last_prompt_used,
            owasp_mapping=attack.owasp_mapping,
            owasp_agentic_mapping=attack.owasp_agentic_mapping,
            atlas_mapping=attack.atlas_mapping,
            harm_category=attack.harm_category,
            token_usage=total_tokens,
        )
