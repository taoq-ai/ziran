"""Evasion-rate metric for campaigns with a declared defence profile.

Per spec 012 (Benchmark Maturity) user story 5 and the contract in
``specs/012-benchmark-maturity/data-model.md``, ``compute_evasion_rate``
returns:

- ``None`` when no profile is declared
- ``None`` when the profile is empty (semantically identical to absent)
- ``None`` when the profile has no evaluable defences (report surface marks
  this as "not computable" while still carrying the declared defences)
- Otherwise, the proportion of successful attacks that bypassed every
  evaluable defence.

This release does not ship any evaluators — all built-in ``DefenceDeclaration``
instances default to ``evaluable=False``, so in practice ``compute_evasion_rate``
will return ``None`` even when a profile is declared. The schema is in place
for future integrations to light up per-finding bypass signals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ziran.domain.entities.attack import AttackResult
    from ziran.domain.entities.defence import DefenceProfile


def compute_evasion_rate(
    findings: Sequence[AttackResult],
    profile: DefenceProfile | None,
) -> float | None:
    """Return the evasion rate for a campaign, or ``None`` when unknowable.

    Args:
        findings: Ordered sequence of :class:`AttackResult` produced by the
            campaign. Only findings where ``successful`` is ``True`` count
            toward the numerator.
        profile: The :class:`DefenceProfile` declared at campaign time (may be
            ``None``).

    Returns:
        The proportion of successful attacks that bypassed all evaluable
        defences, in ``[0.0, 1.0]``, or ``None`` when the metric is not
        computable (no profile, empty profile, or no evaluable defences).
    """
    if profile is None or profile.is_empty:
        return None
    evaluable = profile.evaluable_defences
    if not evaluable:
        # Metadata-only declaration — report carries the profile but omits
        # the metric. Surface as "not computable" in the report layer.
        return None
    if not findings:
        return 0.0
    successful = [f for f in findings if f.successful]
    if not successful:
        return 0.0
    # Each evaluable defence will, in future integrations, stamp a
    # ``defence_bypass`` entry onto the AttackResult's evidence dict. For this
    # release we treat the absence of that stamp as "no bypass observed" — so
    # the ratio is zero when evaluable defences exist but no evaluator has
    # populated the per-finding bypass flag yet. Future PRs light this up
    # without schema change.
    bypasses = sum(
        1
        for finding in successful
        if _finding_bypassed_all(finding, [d.identifier for d in evaluable])
    )
    return round(bypasses / len(successful), 4)


def _finding_bypassed_all(finding: AttackResult, evaluable_ids: list[str]) -> bool:
    """Return True if the finding evidence reports bypasses for every evaluable defence.

    Evidence convention (forward-compatible, set by future evaluator adapters):

        evidence["defence_bypass"] = {
            "<identifier-1>": True,  # bypassed
            "<identifier-2>": False, # caught
        }

    A finding counts as a bypass only when every evaluable defence it targeted
    reports ``True``. Missing keys default to ``False`` (caught by the absent
    defence) so that the zero-evaluator baseline in this release yields a
    zero-bypass count.
    """
    bypass_map: dict[str, bool] = finding.evidence.get("defence_bypass", {})
    return all(bypass_map.get(ident, False) for ident in evaluable_ids)
