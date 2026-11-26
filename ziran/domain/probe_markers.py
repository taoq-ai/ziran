"""Per-probe correlation markers (spec 117).

The attack executor opens a scope per attack; an adapter that sends requests asks for the next
turn's headers. The trace id is one per attack (campaign id and vector id), the W3C parent id
one per turn, so a blue team sees each attack as one trace.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import quote

from ziran.domain.entities.attack import ProbeMarker

if TYPE_CHECKING:
    from collections.abc import Iterator

_scope: ContextVar[tuple[str, str, list[ProbeMarker]] | None] = ContextVar(
    "ziran_probe_scope", default=None
)


@contextmanager
def probe_scope(campaign_id: str, attack_id: str) -> Iterator[list[ProbeMarker]]:
    """Collect the markers the attack's requests carry, in send order."""
    markers: list[ProbeMarker] = []
    token = _scope.set((campaign_id, attack_id, markers))
    try:
        yield markers
    finally:
        _scope.reset(token)


def _hex(text: str, length: int) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:length]


def mark_probe(mode: str | None) -> dict[str, str]:
    """Record the next turn's marker and return its headers; ``{}`` when off or outside an attack."""
    scope = _scope.get()
    if mode is None or scope is None:
        return {}
    campaign_id, attack_id, markers = scope
    attack_key = f"{campaign_id}/{attack_id}"
    probe_id = f"{attack_key}/{len(markers) + 1}"
    trace_id = _hex(attack_key, 32)
    markers.append(ProbeMarker(probe_id=probe_id, trace_id=trace_id, sent_at=datetime.now(UTC)))
    headers: dict[str, str] = {}
    if mode in ("traceparent", "both"):
        headers["traceparent"] = f"00-{trace_id}-{_hex(probe_id, 16)}-01"
    if mode in ("header", "both"):
        headers["X-Ziran-Probe"] = quote(probe_id, safe="/:._-")  # a header value is ASCII
    return headers
