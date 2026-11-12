"""The hybrid detector's model step (spec 064).

The first pass decides every unit alone; ``decide`` then sends a share of the band units to a
model job and takes a reply only when it parses. A unit with a pending or unparsable reply keeps
its deterministic verdict and is listed in ``llm_pending``, so a missing reply never reads as
a negative.

``hybrid_route_share`` (ziran-paper ``prereg/patch-protocol.md`` section 6) is the share of
band units sent, from 0.0 to 1.0. The default 0.0 is deterministic mode: no model call.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import TYPE_CHECKING, Generic, TypeVar

from pydantic import BaseModel

from ziran.infrastructure.llm.replay_client import PendingResponse

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from ziran.application.hybrid.prompts import Prompt
    from ziran.infrastructure.llm.base import BaseLLMClient

V = TypeVar("V")


class HybridResult(BaseModel, Generic[V]):
    """Every unit's verdict, the units sent, and those whose reply was not usable."""

    verdicts: dict[str, V]
    sent: list[str]
    llm_pending: list[str]


def routed(units: Sequence[str], share: float) -> list[str]:
    """The band units sent at ``share``: the first floor(share * n) in sha256-of-id order."""
    if not (isinstance(share, (int, float)) and 0.0 <= share <= 1.0):
        raise ValueError(f"hybrid_route_share must be from 0.0 to 1.0, got {share!r}")
    if len(set(units)) != len(units):
        raise ValueError("duplicate unit ids in the band")
    ordered = sorted(units, key=lambda u: hashlib.sha256(u.encode("utf-8")).hexdigest())
    return ordered[: math.floor(Decimal(str(share)) * len(ordered))]  # 0.29 * 100 is 29, not 28


async def decide(
    deterministic: Mapping[str, V],
    client: BaseLLMClient | None,
    prompt: Prompt,
    render: Callable[[str], str],
    parse: Callable[[str], V | None],
    *,
    share: float = 0.0,
) -> HybridResult[V]:
    """Ask ``client`` about the routed band units; keep the first pass for the rest.

    Args:
        deterministic: each band unit's first-pass verdict, by unit id.
        render: unit id to the rendered request text.
        parse: reply content to a verdict, or None when the reply is not usable.

    Raises:
        ValueError: the share is out of range, or above 0.0 with no client.
    """
    sent = routed(list(deterministic), share)
    if share > 0 and client is None:
        raise ValueError("hybrid_route_share above 0.0 needs a model client")
    verdicts = dict(deterministic)
    pending = []
    for unit in sent:
        assert client is not None  # checked above
        reply = await client.complete(
            [{"role": "user", "content": render(unit)}],
            job=prompt.job,
            unit=unit,
            prompt=prompt.text,
        )
        try:
            verdict = None if isinstance(reply, PendingResponse) else parse(reply.content)
        except ValueError:  # malformed JSON from a live client: not usable, so pending
            verdict = None
        if verdict is None:
            pending.append(unit)
        else:
            verdicts[unit] = verdict
    return HybridResult(verdicts=verdicts, sent=sent, llm_pending=pending)
