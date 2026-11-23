"""The lethal trifecta: one agent that reads private data, sees untrusted content and can send
data out (spec 088).

Each tool gets its *legs* from name rules over :func:`canonical_tool_name` and
:func:`tokens`, or from a caller's override (``trifecta_roles`` in ``.ziran/detectors.yaml``).
A tool can hold several legs: ``WebFetch`` is untrusted content and egress, ``read_inbox``
untrusted content and private data. An agent whose tools cover all three legs gets one
``lethal_trifecta`` chain, whatever order the tools run in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ziran.application.knowledge_graph.graph import EdgeType, NodeType
from ziran.application.knowledge_graph.role_typing import EGRESS, tokens, tool_roles
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.domain.entities.capability import DangerousChain

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

__all__ = ["LEGS", "RULE_ID", "VULNERABILITY_TYPE", "find_trifectas", "tool_legs"]

LEGS: tuple[str, ...] = ("private_data", "untrusted_content", "egress")
RULE_ID = "LT001"  # one SARIF rule id for audit, scan and CI
VULNERABILITY_TYPE = "lethal_trifecta"


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
    reads = "source" in tool_roles(tool_id)
    out = set()
    if toks & SECRET or (reads and toks & PRIVATE):
        out.add("private_data")
    if toks & WEB or (reads and toks & INBOUND):
        out.add("untrusted_content")
    if toks & _SEND or (not reads and toks & _MAIL) or ("fetch" in toks and toks & _PAGE):
        out.add("egress")
    return frozenset(out)


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
    overrides = overrides or {}
    legs: dict[str, frozenset[str]] = {}
    for tid in tool_ids:
        override = overrides.get(tid, overrides.get(tid.removeprefix("tool_")))
        legs[tid] = tool_legs(tid, override)  # validates a caller's override too
    chains: list[DangerousChain] = []
    for agent, tools in _scopes(graph, tool_ids):
        by_leg = {leg: [t for t in tools if leg in legs[t]] for leg in LEGS}
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
                remediation=(
                    "Remove or restrict one leg: drop the egress tool, scope the private data "
                    "tool, or keep untrusted content out of this agent"
                ),
                graph_path=members,
                chain_type="trifecta",
                evidence=evidence,
            )
        )
    return chains
