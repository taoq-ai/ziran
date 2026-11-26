"""Attack execution logic extracted from AgentScanner.

Contains :class:`AttackExecutor` which runs a single :class:`AttackVector`
against the target agent. ``_is_error_response`` is re-exported from :mod:`ziran.domain.replies`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.application.a2a_probe import run_a2a_probe
from ziran.application.agent_scanner.progress import ProgressEmitter
from ziran.application.agent_scanner.streaming import invoke_streaming
from ziran.application.attacks.carrier_executor import CarrierExecutor, CarrierSites
from ziran.application.attacks.many_shot import ShotRenderer, clamp_shots, estimate_tokens
from ziran.application.detectors.ensemble import review_evidence
from ziran.application.detectors.side_effect import get_side_effect_summary
from ziran.application.goals import judge_goal
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    TokenUsage,
    get_business_impacts,
)
from ziran.domain.interfaces.a2a_wire import A2AWire
from ziran.domain.interfaces.adapter import scan_metadata
from ziran.domain.probe_markers import probe_scope
from ziran.domain.replies import ERROR_SENTINELS as _ERROR_SENTINELS
from ziran.domain.replies import is_error_response as _is_error_response
from ziran.infrastructure.logging.context import bind_vector
from ziran.infrastructure.logging.logger import get_logger
from ziran.infrastructure.telemetry.tracing import get_tracer

if TYPE_CHECKING:
    from ziran.application.detectors.pipeline import DetectorPipeline
    from ziran.domain.entities.goal import Replies, Turns
    from ziran.domain.interfaces.adapter import BaseAgentAdapter
    from ziran.infrastructure.llm.base import BaseLLMClient

logger = get_logger(__name__)
_tracer = get_tracer(__name__)

__all__ = ["_ERROR_SENTINELS", "AttackExecutor", "_is_error_response"]


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
        attacker / budget: attacker client and campaign budget (specs 081, 128).
        carriers: Folders where carrier vectors plant files (spec 112).
        campaign_id: Seeds each attack's probe-marker trace id (spec 117).
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
        attacker: BaseLLMClient | None = None,
        budget: CampaignBudget | None = None,
        carriers: CarrierSites | None = None,
        campaign_id: str = "",
    ) -> None:
        self._adapter = adapter
        # Bounded-cardinality provider label for metrics (e.g. "anthropic",
        # "langchain") derived from the adapter class name.
        self.provider = type(adapter).__name__.removesuffix("Adapter").lower() or "unknown"
        self._detector_pipeline = detector_pipeline
        self._streaming = streaming
        self._emitter = emitter or ProgressEmitter()
        self._encoding = encoding
        # Many-shot (spec 023): optional scan-time shot-count override and the
        # target's usable context budget (over-capacity many-shot prompts skip+warn).
        self._n_shots_override = n_shots
        self._context_window = context_window
        self._shot_renderer: ShotRenderer | None = None
        self.attacker = attacker
        self._budget = budget or CampaignBudget(UsageLedger(), UsageBudget())
        self._carrier = CarrierExecutor(adapter, carriers)
        self._campaign_id = campaign_id

    # -- public API --------------------------------------------------------

    @property
    def a2a_wire(self) -> A2AWire | None:
        """The target's A2A probe wire (spec 118), or None when it does not speak A2A."""
        wire = getattr(self._adapter, "a2a_wire", None)
        return wire if isinstance(wire, A2AWire) else None

    async def execute(
        self, attack: AttackVector, *, deadline: float | None = None, trial: int = 0
    ) -> AttackResult:
        """Execute *attack*; *deadline* is a PAIR vector's event-loop stop time (spec 081).
        Its side-effect goal is judged on each reply's recorded tool calls (spec 116), and
        the probe markers its requests carried are recorded on it (spec 117). A repeat
        *trial* (spec 121) gets its own turns and probe trace."""
        turns: Turns = {}
        replies: Replies = {}  # each reply's text, for a secret goal (spec 124)
        scope_id = f"{attack.id}/trial-{trial + 1}" if trial else attack.id
        with probe_scope(self._campaign_id, scope_id) as markers:
            result = await self._run(attack, deadline, turns, replies)
            result = judge_goal(attack, result, turns, replies)
        if markers:
            result.probe_markers = markers
        return result

    def reset_state(self) -> None:
        """Reset the target before a repeat trial (spec 121)."""
        self._adapter.reset_state()

    async def _run(
        self, attack: AttackVector, deadline: float | None, turns: Turns, replies: Replies
    ) -> AttackResult:
        bind_vector(attack.id)
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

        if attack.a2a_probe is not None:  # protocol probe, no prompt (spec 118)
            _attack_span.end()
            return await run_a2a_probe(attack, self.a2a_wire)

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
                owasp_agentic_mapping=attack.owasp_agentic_mapping,
                atlas_mapping=attack.atlas_mapping,
                business_impact=get_business_impacts(attack.category, attack.severity),
                harm_category=attack.harm_category,
            )

        # Delegate multi-turn tactics, and carrier files (spec 112)
        if attack.tactic != "single" or attack.carrier is not None:
            from ziran.application.attacks.campaign import CampaignExecutor
            from ziran.application.attacks.pair import is_pair
            from ziran.application.attacks.tactics import TacticExecutor

            pipeline, render, log = self._detector_pipeline, self._render_prompt, (turns, replies)
            if attack.carrier is not None:
                result = await self._carrier.execute(attack, pipeline, render, *log)
            elif is_pair(attack):  # pair, tap, crescendo_live (specs 081, 128)
                pair = CampaignExecutor(self._adapter, self.attacker, self._budget)
                result = await pair.execute(attack, pipeline, render, *log, deadline=deadline)
            else:
                tactic = TacticExecutor(self._adapter)
                result = await tactic.execute(attack, pipeline, render, *log)
            _attack_span.set_attribute("ziran.attack.successful", result.successful)
            _attack_span.end()
            return result

        attack_tokens = TokenUsage()

        last_response_content: str | None = None
        last_prompt_used: str | None = None

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

        review: dict[str, Any] = {}
        answered = 0  # prompts that reached the detectors; the rest failed (spec 049)

        for turn, (rendered_prompt, enc_label, prompt_spec) in enumerate(prompt_attempts, 1):
            try:
                if self._streaming:
                    response = await invoke_streaming(
                        self._adapter, self._emitter, rendered_prompt, attack.name
                    )
                else:
                    response = await self._adapter.invoke(rendered_prompt)
                plain = rendered_cache[id(prompt_spec)]  # an encoded prompt's own values
                response.metadata = scan_metadata(response.metadata, rendered_prompt, plain)

                attack_tokens = attack_tokens + TokenUsage(
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )

                # Always track the last valid response for reporting
                if response.content and not _is_error_response(response.content):
                    last_response_content = response.content
                    last_prompt_used = rendered_prompt

                if _is_error_response(response.content):
                    continue
                turns[turn], replies[turn] = response.tool_calls, response.content

                verdict = await self._detector_pipeline.evaluate(
                    rendered_prompt,
                    response,
                    prompt_spec,
                    attack,
                )
                answered += 1
                if verdict.needs_review:
                    review = review_evidence(verdict)

                if verdict.successful:
                    side_effects = get_side_effect_summary(response.tool_calls)
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
                            **review_evidence(verdict),
                        },
                        agent_response=response.content,
                        prompt_used=rendered_prompt,
                        encoding_applied=enc_label,
                        owasp_mapping=attack.owasp_mapping,
                        owasp_agentic_mapping=attack.owasp_agentic_mapping,
                        business_impact=get_business_impacts(attack.category, attack.severity),
                        harm_category=attack.harm_category,
                        quality_score=quality,
                        token_usage=attack_tokens,
                    )

            except TimeoutError:
                logger.warning("prompt_timed_out", vector_id=attack.id)
            except (ConnectionError, OSError) as exc:
                logger.warning("prompt_connection_error", vector_id=attack.id, error=str(exc))
            except Exception as e:
                logger.warning("prompt_error", vector_id=attack.id, error=str(e))

        if answered < len(prompt_attempts):  # swallowed failures block caching
            review["prompt_errors"] = len(prompt_attempts) - answered
        if not answered:  # no reply measured this vector (spec 082)
            review["outcome"] = "unmeasured"
        _attack_span.set_attribute("ziran.attack.successful", False)
        _attack_span.end()
        return AttackResult(
            vector_id=attack.id,
            vector_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            successful=False,
            evidence={"note": "All prompts were blocked or failed", **review},
            agent_response=last_response_content,
            prompt_used=last_prompt_used,
            owasp_mapping=attack.owasp_mapping,
            owasp_agentic_mapping=attack.owasp_agentic_mapping,
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
                "many_shot_clamped",
                vector_id=attack.id,
                requested=requested,
                effective=effective,
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
            logger.warning("many_shot_skipped", vector_id=attack.id, reason=reason)
            return AttackResult(
                vector_id=attack.id,
                vector_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                successful=False,
                evidence={"skipped": reason, "n_shots": effective},
                owasp_mapping=attack.owasp_mapping,
                owasp_agentic_mapping=attack.owasp_agentic_mapping,
                atlas_mapping=attack.atlas_mapping,
                business_impact=get_business_impacts(attack.category, attack.severity),
                harm_category=attack.harm_category,
            )

        prompt_attempts[:] = expanded
        return None

    # -- prompt rendering --------------------------------------------------

    @staticmethod
    def _render_prompt(prompt_spec: AttackPrompt) -> str:
        """Render a prompt template with its default variables."""
        template = prompt_spec.template
        for key, value in prompt_spec.variables.items():
            template = template.replace(f"{{{key}}}", value)
        return template.strip()
