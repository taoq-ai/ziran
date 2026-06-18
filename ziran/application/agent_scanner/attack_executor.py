"""Attack execution logic extracted from AgentScanner.

Contains :class:`AttackExecutor` which runs a single :class:`AttackVector`
against the target agent, plus the ``_is_error_response`` sentinel checker.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ziran.application.agent_scanner.progress import (
    ProgressEmitter,
    ProgressEvent,
    ProgressEventType,
)
from ziran.application.attacks.many_shot import ShotRenderer, clamp_shots, estimate_tokens
from ziran.application.detectors.side_effect import get_side_effect_summary
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    TokenUsage,
    get_business_impacts,
)
from ziran.infrastructure.telemetry.tracing import get_tracer

if TYPE_CHECKING:
    from ziran.application.detectors.pipeline import DetectorPipeline
    from ziran.domain.interfaces.adapter import AgentResponse, BaseAgentAdapter

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)

# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_ERROR_SENTINELS: frozenset[str] = frozenset(
    {
        "agent stopped due to iteration limit",
        "agent stopped due to max iterations",
        "agent stopped due to time limit",
    }
)


def _is_error_response(text: str) -> bool:
    """Return *True* when *text* looks like a framework error rather than
    a genuine agent answer.  Used to avoid counting iteration-limit
    timeouts as successful attacks.
    """
    text_lower = text.strip().lower().rstrip(".")
    return any(sentinel in text_lower for sentinel in _ERROR_SENTINELS)


class AttackExecutor:
    """Executes a single :class:`AttackVector` against the target agent.

    Sends each prompt template in the vector, applies optional encoding
    variants, evaluates via the detector pipeline, and returns an
    :class:`AttackResult`.

    Args:
        adapter: Agent adapter for the target agent.
        detector_pipeline: Detection pipeline for evaluating responses.
        streaming: Whether to use streaming invocation.
        emitter: Progress emitter for lifecycle events.
        encoding: Optional list of encoding types to apply.
    """

    def __init__(
        self,
        adapter: BaseAgentAdapter,
        detector_pipeline: DetectorPipeline,
        *,
        streaming: bool = False,
        emitter: ProgressEmitter | None = None,
        encoding: list[str] | None = None,
        n_shots: int | None = None,
        context_window: int = 200_000,
    ) -> None:
        self._adapter = adapter
        self._detector_pipeline = detector_pipeline
        self._streaming = streaming
        self._emitter = emitter or ProgressEmitter()
        self._encoding = encoding
        # Many-shot (spec 023): optional scan-time shot-count override and the
        # target's usable context budget (over-capacity many-shot prompts skip+warn).
        self._n_shots_override = n_shots
        self._context_window = context_window
        self._shot_renderer: ShotRenderer | None = None

    # -- public API --------------------------------------------------------

    async def execute(self, attack: AttackVector) -> AttackResult:
        """Execute *attack* and return the result."""
        _attack_span = _tracer.start_span(
            "ziran.attack",
            attributes={
                "ziran.attack.id": attack.id,
                "ziran.attack.name": attack.name,
                "ziran.attack.category": attack.category.value
                if hasattr(attack.category, "value")
                else str(attack.category),
                "ziran.attack.severity": attack.severity,
                "ziran.attack.tactic": attack.tactic,
            },
        )

        if not attack.prompts:
            _attack_span.set_attribute("ziran.attack.error", "no_prompts")
            _attack_span.end()
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                error="No prompts defined for this attack vector",
                owasp_mapping=attack.owasp_mapping,
                atlas_mapping=attack.atlas_mapping,
                business_impact=get_business_impacts(attack.category, attack.severity),
                harm_category=attack.harm_category,
            )

        # Delegate to TacticExecutor for multi-turn tactics
        if attack.tactic != "single":
            from ziran.application.attacks.tactics import TacticExecutor

            executor = TacticExecutor(self._adapter)
            result = await executor.execute(attack, self._detector_pipeline, self._render_prompt)
            _attack_span.set_attribute("ziran.attack.successful", result.successful)
            _attack_span.end()
            return result

        attack_tokens = TokenUsage()

        # Track last response/prompt for reporting even when all prompts fail
        last_response_content: str | None = None
        last_prompt_used: str | None = None
        encoding_used: str | None = None

        # Build list of (prompt_text, encoding_label) pairs to attempt.
        prompt_attempts: list[tuple[str, str | None, AttackPrompt]] = []
        rendered_cache: dict[int, str] = {}
        for prompt_spec in attack.prompts:
            rendered = self._render_prompt(prompt_spec)
            rendered_cache[id(prompt_spec)] = rendered
            prompt_attempts.append((rendered, None, prompt_spec))

        if self._encoding:
            from ziran.application.attacks.encoding import EncodingType, PromptEncoder

            enc_types = [EncodingType(e) for e in self._encoding]
            for prompt_spec in attack.prompts:
                rendered = rendered_cache[id(prompt_spec)]
                for enc_type in enc_types:
                    encoder = PromptEncoder([enc_type])
                    enc_result = encoder.encode(rendered)
                    prompt_attempts.append((enc_result.encoded, enc_type.value, prompt_spec))

        # Many-shot expansion (spec 023): stack N synthetic shots before each
        # rendered prompt; skip + warn if the result exceeds the context budget.
        if attack.many_shot is not None:
            skip = self._expand_many_shot(attack, prompt_attempts)
            if skip is not None:
                _attack_span.end()
                return skip

        # Try each prompt variant
        for rendered_prompt, enc_label, prompt_spec in prompt_attempts:
            try:
                if self._streaming:
                    response = await self._invoke_streaming(rendered_prompt, attack.name)
                else:
                    response = await self._adapter.invoke(rendered_prompt)

                # Accumulate token usage
                attack_tokens = attack_tokens + TokenUsage(
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )

                # Always track the last valid response for reporting
                if response.content and not _is_error_response(response.content):
                    last_response_content = response.content
                    last_prompt_used = rendered_prompt

                # Error sentinel check
                if _is_error_response(response.content):
                    continue

                # Detector pipeline
                verdict = await self._detector_pipeline.evaluate(
                    rendered_prompt,
                    response,
                    prompt_spec,
                    attack,
                )

                if verdict.successful:
                    side_effects = get_side_effect_summary(response.tool_calls)
                    encoding_used = enc_label
                    _attack_span.set_attribute("ziran.attack.successful", True)
                    _attack_span.add_event("vulnerability_found", {"vector_id": attack.id})
                    _attack_span.end()

                    quality = (
                        verdict.quality_score.composite_score
                        if verdict.quality_score is not None
                        else None
                    )

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
                        },
                        agent_response=response.content,
                        prompt_used=rendered_prompt,
                        encoding_applied=encoding_used,
                        owasp_mapping=attack.owasp_mapping,
                        business_impact=get_business_impacts(attack.category, attack.severity),
                        harm_category=attack.harm_category,
                        quality_score=quality,
                        token_usage=attack_tokens,
                    )

            except TimeoutError:
                logger.warning("Prompt for %s timed out", attack.id)
            except (ConnectionError, OSError) as exc:
                logger.warning("Connection error executing prompt for %s: %s", attack.id, exc)
            except Exception as e:
                logger.warning("Error executing prompt for %s: %s", attack.id, str(e))

        # None of the prompts succeeded
        _attack_span.set_attribute("ziran.attack.successful", False)
        _attack_span.end()
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            successful=False,
            evidence={"note": "All prompts were blocked or failed"},
            agent_response=last_response_content,
            prompt_used=last_prompt_used,
            owasp_mapping=attack.owasp_mapping,
            atlas_mapping=attack.atlas_mapping,
            business_impact=get_business_impacts(attack.category, attack.severity),
            harm_category=attack.harm_category,
            token_usage=attack_tokens,
        )

    # -- many-shot (spec 023) ---------------------------------------------

    def _expand_many_shot(
        self,
        attack: AttackVector,
        prompt_attempts: list[tuple[str, str | None, AttackPrompt]],
    ) -> AttackResult | None:
        """Prepend N synthetic shots to each prompt in place.

        Returns a skipped ``AttackResult`` when every expanded prompt exceeds the
        target's context budget (skip + warn — FR-007); otherwise mutates
        *prompt_attempts* to the expanded prompts and returns ``None``.
        """
        config = attack.many_shot
        assert config is not None
        if self._shot_renderer is None:
            self._shot_renderer = ShotRenderer()
        requested = self._n_shots_override if self._n_shots_override is not None else config.n_shots
        effective, clamped = clamp_shots(requested)
        if clamped:
            logger.warning(
                "Many-shot %s: requested n_shots=%s clamped to %s", attack.id, requested, effective
            )
        shots = self._shot_renderer.render(config.corpus, effective)

        expanded: list[tuple[str, str | None, AttackPrompt]] = []
        for rendered, enc, spec in prompt_attempts:
            prompt = f"{shots}\n\n{rendered}"
            if estimate_tokens(prompt) <= self._context_window:
                expanded.append((prompt, enc, spec))

        if not expanded:
            smallest_prompt_tokens = min(
                estimate_tokens(f"{shots}\n\n{rendered}") for rendered, _, _ in prompt_attempts
            )
            reason = (
                f"target context too small for {effective} shots "
                f"(~{smallest_prompt_tokens} prompt tokens > {self._context_window} budget)"
            )
            logger.warning("Many-shot %s skipped: %s", attack.id, reason)
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                evidence={"skipped": reason, "n_shots": effective},
                owasp_mapping=attack.owasp_mapping,
                atlas_mapping=attack.atlas_mapping,
                business_impact=get_business_impacts(attack.category, attack.severity),
                harm_category=attack.harm_category,
            )

        prompt_attempts[:] = expanded
        return None

    # -- streaming ---------------------------------------------------------

    async def _invoke_streaming(
        self,
        prompt: str,
        attack_name: str,
    ) -> AgentResponse:
        """Invoke the agent with streaming and accumulate into AgentResponse."""
        from ziran.domain.interfaces.adapter import AgentResponse

        content_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {}

        async for chunk in self._adapter.stream(prompt):
            if chunk.content_delta:
                content_parts.append(chunk.content_delta)

            if chunk.tool_call_delta:
                tool_calls.append(chunk.tool_call_delta)

            # Emit streaming progress event
            self._emitter.emit(
                ProgressEvent(
                    event=ProgressEventType.ATTACK_STREAMING,
                    attack_name=attack_name,
                    message=chunk.content_delta,
                    extra={
                        "is_final": chunk.is_final,
                        "chunk_metadata": chunk.metadata,
                    },
                )
            )

            if chunk.is_final:
                metadata = chunk.metadata

        content = "".join(content_parts)
        final_tool_calls = metadata.get("tool_calls", tool_calls)

        return AgentResponse(
            content=content,
            tool_calls=final_tool_calls,
            metadata=metadata,
            prompt_tokens=metadata.get("prompt_tokens", 0),
            completion_tokens=metadata.get("completion_tokens", 0),
            total_tokens=metadata.get("total_tokens", 0),
        )

    # -- prompt rendering --------------------------------------------------

    @staticmethod
    def _render_prompt(prompt_spec: AttackPrompt) -> str:
        """Render a prompt template with its default variables."""
        template = prompt_spec.template
        for key, value in prompt_spec.variables.items():
            template = template.replace(f"{{{key}}}", value)
        return template.strip()
