"""Capability roles of a tool from its name (spec 066; the action-verb rule of spec 099).

A caller that knows a tool's roles (a catalogue entry, a stored classifier reply) passes
them as the override. An override that gives a role is never overruled. Every other tool
is typed one way, whatever the reason it has no model role (no reply, an unusable reply,
a reply that gives no role):

- A tool the alias table knows (:func:`canonical_tool_name` maps it) keeps the V2 name
  rules of the G-10 dev probe on its table keyword: a *source* when the first token is a
  read verb or any token is a source token, and a sink of each role whose words it holds.
- Any other tool is typed by the first read or write verb of its *own name*: the part
  after ``mcp__<server>__``, the part after the toolkit name when the caller knows it,
  else the whole id. A read verb makes a reader: a *source*, with no sink role from a
  later noun. A write verb makes an actor, with the sink roles the verb names, or
  *high_impact* when it names none. A name with no listed verb is an actor.

The word lists are those of ``study/scripts/g10_dev_probe.py`` in taoq-ai/ziran-paper at
f80204a, verbatim.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.detectors.provenance import READ_VERBS, WRITE_VERBS, tokens
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "READ_VERBS",
    "ROLES",
    "SINKS",
    "TYPED_VULNERABILITY_TYPES",
    "keyword_roles",
    "tokens",
    "tool_roles",
]

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

_SINK_WORDS = (("egress", EGRESS), ("exec", EXEC), ("high_impact", HIGH))

SINKS: frozenset[str] = frozenset({"egress", "exec", "high_impact"})
ROLES: frozenset[str] = SINKS | {"source"}

#: One vulnerability type per sink role. Only the egress type meets the exfiltration-class
#: rule (``exfil|leak``) of ziran-paper's preregistration, section 4.
TYPED_VULNERABILITY_TYPES: dict[str, str] = {
    "egress": "typed_data_exfiltration",
    "exec": "typed_untrusted_execution",
    "high_impact": "typed_high_impact_action",
}


def keyword_roles(tool_id: str) -> frozenset[str]:
    """The V2 word rules on the tool's table keyword: what a table tool keeps, and what the
    scan's blast radius and trifecta legs read, which the verb rule does not change."""
    toks = tokens(canonical_tool_name(tool_id))
    out = set()
    if toks and (toks[0] in READ_VERBS or any(t in SOURCE_TOKENS for t in toks)):
        out.add("source")
    return frozenset(out | {r for r, words in _SINK_WORDS if any(t in words for t in toks)})


def _own_name(tool_id: str, toolkit: str | None) -> str:
    """The part of an id that names the tool: no MCP server prefix, no toolkit name."""
    if tool_id.startswith("mcp__"):
        parts = tool_id.split("__", 2)
        return parts[2] if len(parts) == 3 else tool_id
    if toolkit and tool_id.startswith(toolkit):
        return tool_id[len(toolkit) :]
    return tool_id


def tool_roles(
    tool_id: str, override: Iterable[str] | None = None, *, toolkit: str | None = None
) -> frozenset[str]:
    """The tool's roles: the override when it gives one, else the name rules.

    Raises:
        ValueError: the override holds a role outside :data:`ROLES`.
    """
    if override is not None:
        roles = frozenset(override)
        if isinstance(override, str) or not roles <= ROLES:
            raise ValueError(f"role override for {tool_id!r} must be a set of {sorted(ROLES)}")
        if roles:
            return roles
    if canonical_tool_name(tool_id) != tool_id:  # a table tool keeps its roles
        return keyword_roles(tool_id)
    if not tokens(tool_id):
        return frozenset()  # a blank id names no tool
    own = tokens(_own_name(tool_id, toolkit))
    verb = next((t for t in own if t in READ_VERBS or t in WRITE_VERBS), None)
    if verb in READ_VERBS:
        return frozenset({"source"})
    return frozenset({r for r, words in _SINK_WORDS if verb in words} or {"high_impact"})
