"""The lethal trifecta: one agent that reads private data, sees untrusted content and can send
data out (spec 088).

Each tool gets its *legs* from name rules over :func:`canonical_tool_name` and
:func:`tokens`, or from a caller's override (``trifecta_roles`` in ``.ziran/detectors.yaml``).
A tool can hold several legs: ``WebFetch`` is untrusted content and egress, ``read_inbox``
untrusted content and private data. An agent whose tools cover all three legs gets one
``lethal_trifecta`` chain, whatever order the tools run in. An agent that covers them only with
the agents it delegates to gets one ``lethal_trifecta_delegated`` chain (slice 2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.graph import EdgeType, NodeType
from ziran.application.knowledge_graph.role_typing import EGRESS, keyword_roles, tokens
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.domain.entities.capability import DangerousChain

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

__all__ = [
    "DELEGATED_RULE_ID",
    "DELEGATED_TYPE",
    "LEGS",
    "RULE_ID",
    "VULNERABILITY_TYPE",
    "egress_after_untrusted",
    "find_trifectas",
    "tool_legs",
]

LEGS: tuple[str, ...] = ("private_data", "untrusted_content", "egress")
RULE_ID = "LT001"  # one SARIF rule id for audit, scan and CI
VULNERABILITY_TYPE = "lethal_trifecta"
DELEGATED_TYPE = "lethal_trifecta_delegated"
DELEGATED_RULE_ID = "LT002"  # scan SARIF only: audit agents have no delegation edges
_REMEDIATION = (
    "Remove or restrict one leg: drop the egress tool, scope the private data "
    "tool, or keep untrusted content out of this agent"
)


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


#: Data a reading tool returns that the user would not publish.
PRIVATE = _words(
    """file files inbox email emails mail mails message messages customer customers user users
contact contacts account accounts profile profiles record records database db sql document
documents doc docs drive calendar note notes crm ticket tickets order orders invoice invoices
memory vector"""
)
#: Private on any access, read verb or not.
SECRET = _words("secret secrets credential credentials password passwords")
#: Content from outside the user's control, read or not.
WEB = _words("http https url urls web webpage website browse scrape crawl download rss feed")
#: Outside content only when the tool reads it: ``read_inbox``, not ``send_email``.
INBOUND = _words(
    "inbox email emails mail mails message messages comment comments issue issues chat review"
)
#: role_typing's egress words, less the three that also name reads (``fetch_customer``,
#: ``read_email``); those count below only in a sending form.
_SEND = EGRESS - {"fetch", "email", "message"}
_MAIL = _words("email mail message")
_PAGE = _words("url web webpage website page http https")


def tool_legs(tool_id: str, override: Iterable[str] | None = None) -> frozenset[str]:
    """The tool's legs: the override when given, else the name rules.

    Raises:
        ValueError: the override holds a leg outside :data:`LEGS`.
    """
    if override is not None:
        legs = frozenset(override)
        if isinstance(override, str) or not legs <= set(LEGS):
            raise ValueError(f"trifecta override for {tool_id!r} must be a set of {list(LEGS)}")
        return legs
    toks = set(tokens(canonical_tool_name(tool_id)))
    reads = "source" in keyword_roles(tool_id)
    out = set()
    if toks & SECRET or (reads and toks & PRIVATE):
        out.add("private_data")
    if toks & WEB or (reads and toks & INBOUND):
        out.add("untrusted_content")
    if toks & _SEND or (not reads and toks & _MAIL) or ("fetch" in toks and toks & _PAGE):
        out.add("egress")
    return frozenset(out)


def _legs(tool_id: str, overrides: Mapping[str, Iterable[str]] | None) -> frozenset[str]:
    """The legs of *tool_id*, with an override by id or by name without the ``tool_`` prefix."""
    overrides = overrides or {}
    return tool_legs(tool_id, overrides.get(tool_id, overrides.get(tool_id.removeprefix("tool_"))))


def egress_after_untrusted(
    calls: Iterable[str], overrides: Mapping[str, Iterable[str]] | None = None
) -> bool:
    """Whether an egress call comes after an untrusted content call, in call order.

    "After" is a later call: one call holding both legs (``WebFetch``) sends its request
    before its content arrives. One pass, legs looked up once per tool name.
    """
    legs: dict[str, frozenset[str]] = {}
    seen_untrusted = False
    for call in calls:
        if call not in legs:
            legs[call] = _legs(call, overrides)
        if seen_untrusted and "egress" in legs[call]:
            return True
        seen_untrusted = seen_untrusted or "untrusted_content" in legs[call]
    return False


def _scopes(graph: AttackKnowledgeGraph, tool_ids: list[str]) -> list[tuple[str | None, list[str]]]:
    """Each agent node's ``USES_TOOL`` tools, then one scope for the tools no agent lists.

    A flat agent has no agent node, so its scope is every tool (spec 086's co-resident sets).
    """
    known = set(tool_ids)
    g = graph.structure_view()
    scopes: list[tuple[str | None, list[str]]] = []
    listed: set[str] = set()
    for node, data in graph.graph.nodes(data=True):
        if data.get("node_type") != NodeType.AGENT:
            continue
        own = {v for _, v, et in g.out_edges(node, data="edge_type") if et == EdgeType.USES_TOOL}
        own &= known
        tools = [t for t in tool_ids if t in own]
        listed.update(tools)
        scopes.append((node, tools))
    scopes.append((None, [t for t in tool_ids if t not in listed]))
    return scopes


def find_trifectas(
    graph: AttackKnowledgeGraph,
    tool_ids: list[str],
    overrides: Mapping[str, Iterable[str]] | None = None,
) -> list[DangerousChain]:
    """One ``lethal_trifecta`` chain per agent whose tools cover all three legs.

    *overrides* maps a tool id, or its name without the adapters' ``tool_`` prefix, to its
    legs. The cost and the output are linear in the tools: no pair or path is walked, and
    ``tools`` holds at most three ids.
    """
    legs = {tid: _legs(tid, overrides) for tid in tool_ids}  # validates an override too
    chains: list[DangerousChain] = []
    by_agent: dict[str, dict[str, list[str]]] = {}
    for agent, tools in _scopes(graph, tool_ids):
        by_leg = {leg: [t for t in tools if leg in legs[t]] for leg in LEGS}
        if agent is not None:
            by_agent[agent] = by_leg
        if not all(by_leg.values()):
            continue
        # tools: the first tool of each leg, so the finding node id and its attack paths stay
        # at three ids whatever the tool count; the evidence lists every leg tool once
        witness = {by_leg[leg][0] for leg in LEGS}
        members = [t for t in tools if t in witness]
        evidence: dict[str, object] = dict(by_leg)
        if agent is not None:
            evidence["agent"] = agent
        chains.append(
            DangerousChain(
                tools=members,
                risk_level="critical",
                vulnerability_type=VULNERABILITY_TYPE,
                exploit_description=(
                    "One agent reads private data, sees untrusted content and can send data "
                    "out: a prompt injection in the untrusted content can make it send the "
                    "private data to an attacker"
                ),
                remediation=_REMEDIATION,
                graph_path=members,
                chain_type="trifecta",
                evidence=evidence,
            )
        )
    chains.extend(_delegated(graph, by_agent))
    return chains


def _delegated(
    graph: AttackKnowledgeGraph, by_agent: dict[str, dict[str, list[str]]]
) -> list[DangerousChain]:
    """One ``lethal_trifecta_delegated`` chain per agent that covers the legs only with the
    agents it reaches along ``DELEGATES_TO`` edges.

    An agent that holds all three legs, or reaches one that does, has the plain finding. Each
    walk is breadth first on the structure view; a chain names at most four agents (the
    delegating one, then the first holder of each leg) and three tools, and its evidence the
    first tool of each leg: many agents reaching one large agent must not copy its tools each.
    """
    g = graph.structure_view()
    full = {a for a, own in by_agent.items() if all(own.values())}
    chains: list[DangerousChain] = []
    for agent in by_agent:
        reach, seen = [agent], {agent}
        for a in reach:
            for _, b, et in g.out_edges(a, data="edge_type"):
                if et == EdgeType.DELEGATES_TO and b in by_agent and b not in seen:
                    seen.add(b)
                    reach.append(b)
        if seen & full:
            continue
        holder = {
            leg: next(a for a in reach if by_agent[a][leg])
            for leg in LEGS
            if any(by_agent[a][leg] for a in reach)
        }
        if len(holder) < len(LEGS):
            continue
        names = list(dict.fromkeys([agent, *holder.values()]))
        first = {leg: by_agent[holder[leg]][leg][0] for leg in LEGS}
        members = list(dict.fromkeys(first.values()))
        evidence: dict[str, object] = {leg: [tool] for leg, tool in first.items()}
        chains.append(
            DangerousChain(
                tools=members,
                risk_level="critical",
                vulnerability_type=DELEGATED_TYPE,
                exploit_description=(
                    f"Agent {agent!r} and the agents it delegates to read private data, see "
                    "untrusted content and can send data out: a prompt injection can move the "
                    "private data to the egress tool through the delegation"
                ),
                remediation=_REMEDIATION + ", or stop the delegation that joins the legs",
                graph_path=members,
                chain_type="trifecta",
                evidence=evidence | {"agent": agent, "agents": names},
            )
        )
    return chains
