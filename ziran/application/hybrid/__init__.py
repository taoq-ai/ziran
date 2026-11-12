"""The hybrid detector's model step (spec 064).

The first pass decides every unit alone. ``decide`` sends a share of the band units (patch
protocol section 2) to a model job; a unit outside the band is never sent and keeps its
first-pass verdict. A usable reply is combined with the first-pass verdict by the job's
``merge`` rule, so a reply cannot remove a first-pass decision the protocol keeps (a provenance
hit stays an attempt). A unit with a pending or unparsable reply keeps its first-pass verdict and
is listed in ``llm_pending`` with its cause, so a missing reply never reads as a negative.

``hybrid_route_share`` (ziran-paper ``prereg/patch-protocol.md`` section 6) is the share of
band units sent, from 0.0 to 1.0. The default 0.0 is deterministic mode: no model call.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import TYPE_CHECKING, Generic, TypeVar

from pydantic import BaseModel

# the port module, not an adapter: the pending type sits beside LLMResponse
from ziran.infrastructure.llm.base import PendingResponse

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping, Sequence

    from ziran.application.hybrid.prompts import Prompt
    from ziran.infrastructure.llm.base import BaseLLMClient

V = TypeVar("V")
UNUSABLE = "unusable_reply"  # a reply came back but the job's parse refused it


class HybridResult(BaseModel, Generic[V]):
    """Every unit's verdict, the band units sent, and each sent unit with no usable reply,
    mapped to its cause: the pending reason (``recorded``, ``missing`` or the sender's outcome
    class) or ``unusable_reply``."""

    verdicts: dict[str, V]
    sent: list[str]
    llm_pending: dict[str, str]


def routed(units: Sequence[str], share: float) -> list[str]:
    """The band units sent at ``share``: the first floor(share * n) in sha256-of-id order."""
    ok = isinstance(share, (int, float)) and not isinstance(share, bool)
    if not (ok and 0.0 <= share <= 1.0):
        raise ValueError(f"hybrid_route_share must be from 0.0 to 1.0, got {share!r}")
    if len(set(units)) != len(units):
        raise ValueError("duplicate unit ids in the band")
    ordered = sorted(units, key=lambda u: hashlib.sha256(u.encode("utf-8")).hexdigest())
    return ordered[: math.floor(Decimal(str(share)) * len(ordered))]  # 0.29 * 100 is 29, not 28


async def decide(
    first_pass: Mapping[str, V],
    band: Collection[str],
    client: BaseLLMClient | None,
    prompt: Prompt,
    render: Callable[[str], str],
    parse: Callable[[str], V | None],
    *,
    merge: Callable[[V, V], V],
    share: float = 0.0,
) -> HybridResult[V]:
    """Ask ``client`` about the routed band units; keep the first pass for every other unit.

    Args:
        first_pass: every unit's first-pass verdict, by unit id.
        band: the units the first pass leaves open; only these are ever sent.
        render: unit id to the rendered request text.
        parse: reply content to a verdict, or None when the reply is not usable.
        merge: the job's rule, (first-pass verdict, reply verdict) to the unit's verdict.

    Raises:
        ValueError: a band unit has no first-pass verdict, the share is out of range, or the
            share is above 0.0 with no client.
    """
    if not set(band) <= set(first_pass):
        raise ValueError("every band unit needs a first-pass verdict")
    sent = routed(list(band), share)
    if share > 0 and client is None:
        raise ValueError("hybrid_route_share above 0.0 needs a model client")
    verdicts = dict(first_pass)
    pending: dict[str, str] = {}
    for unit in sent:
        assert client is not None  # checked above
        reply = await client.complete(
            [{"role": "user", "content": render(unit)}],
            job=prompt.job,
            unit=unit,
            prompt=prompt.text,
        )
        if isinstance(reply, PendingResponse):
            pending[unit] = reply.reason
            continue
        try:
            verdict = parse(reply.content)
        except ValueError:  # malformed JSON from a live client: not usable
            verdict = None
        if verdict is None:
            pending[unit] = UNUSABLE
        else:
            verdicts[unit] = merge(first_pass[unit], verdict)
    return HybridResult(verdicts=verdicts, sent=sent, llm_pending=pending)
