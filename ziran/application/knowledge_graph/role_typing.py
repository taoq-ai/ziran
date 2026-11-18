"""Capability roles of a tool from its name: variant V2 of the G-10 dev probe (spec 066).

A tool is a *source* when its first name token is a read verb or any token is a source
token, and a sink of each role whose words it holds: *egress*, *exec* or *high_impact*.
The lists are those of ``study/scripts/g10_dev_probe.py`` in taoq-ai/ziran-paper at
f80204a, verbatim; the name is first mapped by :func:`canonical_tool_name`, as the probe
did. A caller that knows a tool's roles (a catalogue entry, a stored classifier reply)
passes them as the override, and the name rules are not consulted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.detectors.provenance import READ_VERBS, tokens
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["READ_VERBS", "ROLES", "SINKS", "TYPED_VULNERABILITY_TYPES", "tokens", "tool_roles"]

# ── Appendix A of the runbook of 2026-11-11, verbatim ────────────────


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


SOURCE_TOKENS = _words(
    """read query get list search fetch load scan view retrieve download select lookup find
show loader browse scrape crawl diff log"""
)
EGRESS = _words(
    """send post publish upload share forward reply notify webhook push export tweet request
requests http curl fetch email message invite transfer pay"""
)
EXEC = _words(
    "execute exec run shell bash repl eval command deploy interpreter terminal subprocess"
)
HIGH = _words(
    """transfer pay delete remove grant revoke invite unlock withdraw deploy purchase buy order cancel
drop wipe erase kill terminate"""
)

SINKS: frozenset[str] = frozenset({"egress", "exec", "high_impact"})
ROLES: frozenset[str] = SINKS | {"source"}

#: One vulnerability type per sink role. Only the egress type meets the exfiltration-class
#: rule (``exfil|leak``) of ziran-paper's preregistration, section 4.
TYPED_VULNERABILITY_TYPES: dict[str, str] = {
    "egress": "typed_data_exfiltration",
    "exec": "typed_untrusted_execution",
    "high_impact": "typed_high_impact_action",
}


def tool_roles(tool_id: str, override: Iterable[str] | None = None) -> frozenset[str]:
    """The tool's roles: the override when given, else the V2 name rules.

    Raises:
        ValueError: the override holds a role outside :data:`ROLES`.
    """
    if override is not None:
        roles = frozenset(override)
        if isinstance(override, str) or not roles <= ROLES:
            raise ValueError(f"role override for {tool_id!r} must be a set of {sorted(ROLES)}")
        return roles
    toks = tokens(canonical_tool_name(tool_id))
    out = set()
    if toks and (toks[0] in READ_VERBS or any(t in SOURCE_TOKENS for t in toks)):
        out.add("source")
    for role, words in (("egress", EGRESS), ("exec", EXEC), ("high_impact", HIGH)):
        if any(t in words for t in toks):
            out.add(role)
    return frozenset(out)
