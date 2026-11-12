"""Parity: tool_roles() and the typed chains against the frozen G-10 dev probe's V2 (spec 066).

The oracle below is copied verbatim from ``study/scripts/g10_dev_probe.py`` in
taoq-ai/ziran-paper at commit f80204a6a3424fbae33a05e4977de12916088978 (lines 69 to 91,
94, 111 to 115 and 272 to 284), the code that counted the registered dev numbers. It is
kept unformatted so a reader can diff it against the probe. The probe typed each name
after ziran's ``canonical_tool_name``, as ziran does.

V2's sink roles are ``egress``, ``exec`` and ``high``; ziran names the last
``high_impact``. The probe's ``write`` role is no V2 sink and ziran does not report it.
"""

# ruff: noqa
# mypy: ignore-errors

from __future__ import annotations

import random
import re
from collections.abc import Callable
from itertools import permutations
from types import SimpleNamespace

import pytest

from ziran.application.knowledge_graph import role_typing as module
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.knowledge_graph.role_typing import tool_roles
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name

pytestmark = pytest.mark.unit

# ── Oracle: the probe, copied ────────────────────────────────────────
# fmt: off

def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


READ_VERBS = _words("""get read list search find view check fetch query lookup show describe retrieve count is
has validate verify summarize analyze compute calculate translate parse browse visit navigate scrape crawl load
select see watch monitor inspect compare estimate predict classify detect download open look scan preview peek test
ping resolve status info""")
WRITE_VERBS = _words("""send post create update delete remove write transfer pay schedule reschedule reserve book
invite add share grant revoke execute exec run deploy upload publish reply forward cancel modify set change append
move rename purchase buy order withdraw unlock lock edit insert drop kill install commit push merge approve reject
submit register subscribe unsubscribe enable disable reset assign put patch save import export sign deposit refund
charge trigger invoke launch terminate shutdown restart apply overwrite replace clear wipe erase ban block unblock
mute kick email message notify tweet comment like follow unfollow upvote downvote call dial text""")
SOURCE_TOKENS = _words("""read query get list search fetch load scan view retrieve download select lookup find
show loader browse scrape crawl diff log""")
EGRESS = _words("""send post publish upload share forward reply notify webhook push export tweet request
requests http curl fetch email message invite transfer pay""")
EXEC = _words("execute exec run shell bash repl eval command deploy interpreter terminal subprocess")
HIGH = _words("""transfer pay delete remove grant revoke invite unlock withdraw deploy purchase buy order cancel
drop wipe erase kill terminate""")
VARIANTS = {"V1": frozenset({"egress"}), "V2": frozenset({"egress", "exec", "high"}),
            "V3": frozenset({"egress", "exec", "high", "write"})}

_CAMEL = (re.compile(r"([a-z0-9])([A-Z])"), re.compile(r"([A-Z]+)([A-Z][a-z])"))

def tokens(name: str) -> list[str]:
    """Split on non-alphanumerics and CamelCase boundaries; lowercase."""
    for pattern in _CAMEL:
        name = pattern.sub(r"\1 \2", name)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", name) if t]

def roles(name: str, canonical: Callable[[str], str]) -> set[str]:
    toks = tokens(canonical(name))
    out = set()
    if toks and (toks[0] in READ_VERBS or any(t in SOURCE_TOKENS for t in toks)):
        out.add("source")
    for role, words in (("egress", EGRESS), ("exec", EXEC), ("high", HIGH), ("write", WRITE_VERBS)):
        if any(t in words for t in toks):
            out.add(role)
    return out


def typed(source_roles: set[str], sink_roles: set[str]) -> dict[str, bool]:
    return {v: "source" in source_roles and bool(sink_roles & sinks) for v, sinks in VARIANTS.items()}

# fmt: on
# ── The comparison ───────────────────────────────────────────────────

ZIRAN_NAME = {"source": "source", "egress": "egress", "exec": "exec", "high": "high_impact"}


def probe_roles(name: str) -> frozenset[str]:
    return frozenset(ZIRAN_NAME[r] for r in roles(name, canonical_tool_name) if r in ZIRAN_NAME)


def test_lists_equal_the_probe_literals() -> None:
    assert module.READ_VERBS == READ_VERBS
    assert module.SOURCE_TOKENS == SOURCE_TOKENS
    assert module.EGRESS == EGRESS
    assert module.EXEC == EXEC
    assert module.HIGH == HIGH
    assert module.SINKS == frozenset(ZIRAN_NAME[r] for r in VARIANTS["V2"])
    assert module.tokens("getHTTPResponse_v2") == tokens("getHTTPResponse_v2")


_WORDS = sorted(READ_VERBS | WRITE_VERBS | SOURCE_TOKENS | EGRESS | EXEC | HIGH) + [
    "file",
    "inbox",
    "calendar",
    "acme",
    "gateway",
    "user",
    "x",
    "2",
    "v2",
    "data",
    "",
]
_FIXED = [
    "Read",
    "Bash",
    "Bash(*)",
    "Bash(git push:*)",
    "Read(./.env)",
    "WebFetch",
    "WebSearch",
    "Write",
    "Agent",
    "TavilySearchResults",
    "tool_recursive_url_loader",
    "read_secrets",
    "execute_command",
    "mcp__slack__slack_send_message",
    "mcp__github__create_issue",
    "mcp__fs__read_file",
    "mcp__x",
    "",
    "_",
    "123",
    "getSendQueue",
    "HTTPRequest",
    "send_email",
    "read_file",
    "http_request",
]


def _name(rng: random.Random) -> str:
    words = [rng.choice(_WORDS) for _ in range(rng.randint(1, 4))]
    style = rng.randrange(5)
    if style == 0:
        return "".join(w[:1].upper() + w[1:] for w in words)
    if style == 1:
        return words[0] + "".join(w[:1].upper() + w[1:] for w in words[1:])
    if style == 2:
        return "mcp__" + rng.choice(["slack", "gmail", "files", "run"]) + "__" + "_".join(words)
    return rng.choice(["_", "-", ".", " ", "__"]).join(words)


NAMES = _FIXED + [_name(random.Random(seed)) for seed in range(3000)]


def test_name_rules_equal_the_probe_on_every_name() -> None:
    differ = [n for n in NAMES if tool_roles(n) != probe_roles(n)]
    assert differ == []
    # the names reach every role, both kinds of source, and names with no role
    seen = [tool_roles(n) for n in NAMES]
    for role in ("source", "egress", "exec", "high_impact"):
        assert sum(role in r for r in seen) > 100, role
    assert sum(not r for r in seen) > 100


def test_typed_pairs_equal_the_probe_v2_on_seeded_agents() -> None:
    rng = random.Random(20261112)
    checked = 0
    for _ in range(150):
        tools = sorted(
            {rng.choice(NAMES[: len(_FIXED) + 400]) for _ in range(rng.randint(2, 5))} - {""}
        )
        if len(tools) < 2:
            continue
        graph = AttackKnowledgeGraph()
        for t in tools:
            graph.add_tool(t)
        for a, b in permutations(tools, 2):
            graph.add_tool_chain([a, b], risk_score=0.5)
        found = ToolChainAnalyzer(graph, typed=True).analyze(include_cycles=False)
        table = {tuple(c.tools) for c in found if not c.typed}
        got = {tuple(c.tools) for c in found if c.typed}
        want = {
            (a, b)
            for a, b in permutations(tools, 2)
            if typed(roles(a, canonical_tool_name), roles(b, canonical_tool_name))["V2"]
        } - table
        assert got == want, tools
        checked += bool(want)
    assert checked > 20
