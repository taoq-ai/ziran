"""Prompt-attempt building and many-shot expansion, moved out of ``attack_executor``.

:func:`build_prompt_attempts` lists the (prompt, encoding label, spec) triples
:class:`AttackExecutor` sends; :func:`expand_many_shot` prepends synthetic shots
(spec 023).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.attacks.many_shot import ShotRenderer, clamp_shots, estimate_tokens
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    get_business_impacts,
)
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)

PromptAttempts = list[tuple[str, str | None, AttackPrompt]]


def build_prompt_attempts(
    attack: AttackVector,
    render: Callable[[AttackPrompt], str],
    encoding: list[str] | None,
) -> tuple[PromptAttempts, dict[int, str]]:
    """Return the prompt attempts and the rendered text of each prompt spec."""
    prompt_attempts: PromptAttempts = []
    rendered_cache: dict[int, str] = {}
    for prompt_spec in attack.prompts:
        rendered = render(prompt_spec)
        rendered_cache[id(prompt_spec)] = rendered
        prompt_attempts.append((rendered, None, prompt_spec))

    if encoding:
        from ziran.application.attacks.encoding import EncodingType, PromptEncoder

        enc_types = [EncodingType(e) for e in encoding]
        for prompt_spec in attack.prompts:
            rendered = rendered_cache[id(prompt_spec)]
            for enc_type in enc_types:
                encoder = PromptEncoder([enc_type])
                enc_result = encoder.encode(rendered)
                prompt_attempts.append((enc_result.encoded, enc_type.value, prompt_spec))
    return prompt_attempts, rendered_cache


def expand_many_shot(
    attack: AttackVector,
    prompt_attempts: PromptAttempts,
    shot_renderer: ShotRenderer,
    n_shots_override: int | None,
    context_window: int,
) -> AttackResult | None:
    """Prepend N synthetic shots to each prompt in place.

    Returns a skipped ``AttackResult`` when every expanded prompt exceeds the
    target's context budget (skip + warn — FR-007); otherwise mutates
    *prompt_attempts* to the expanded prompts and returns ``None``.
    """
    config = attack.many_shot
    assert config is not None
    requested = n_shots_override if n_shots_override is not None else config.n_shots
    effective, clamped = clamp_shots(requested)
    if clamped:
        logger.warning(
            "many_shot_clamped",
            vector_id=attack.id,
            requested=requested,
            effective=effective,
        )
    shots = shot_renderer.render(config.corpus, effective)

    expanded: PromptAttempts = []
    for rendered, enc, spec in prompt_attempts:
        prompt = f"{shots}\n\n{rendered}"
        if estimate_tokens(prompt) <= context_window:
            expanded.append((prompt, enc, spec))

    if not expanded:
        smallest_prompt_tokens = min(
            estimate_tokens(f"{shots}\n\n{rendered}") for rendered, _, _ in prompt_attempts
        )
        reason = (
            f"target context too small for {effective} shots "
            f"(~{smallest_prompt_tokens} prompt tokens > {context_window} budget)"
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
