"""Claude Code and LangChain-style tool-name aliases for chain matching.

This is the single shared tool-name vocabulary used by chain analysis
(:mod:`ziran.application.knowledge_graph.chain_analyzer`) and trace
analysis (#421). Do not duplicate it elsewhere; import from here, and only
from application-layer code.

:func:`canonical_tool_name` maps a Claude Code tool id (``Read``, ``Bash``,
``mcp__slack__slack_send_message``, ``Read(./.env)`` ...) to the capability
keyword the chain patterns already use. A sink that its permission specifier limits to named
commands or domains (``Bash(git status:*)``, ``WebFetch(domain:docs.example.org)``) maps to
:data:`CONFINED`, which no pattern and no role matches; a ``Bash`` rule for pushing to a
remote stays a sink. Ids that are not Claude Code tools
are checked against a short table of LangChain-style names
(``recursive_url_loader``, ``tavily_search``, ``vector_store_query``,
``read_secrets``, ``execute_command`` and their variants); any other id is returned unchanged. The result is for matching
only; node ids and reported findings keep the original names.
"""

from __future__ import annotations

import re

_BUILTIN_ALIASES: dict[str, str] = {
    "Read": "read_file",
    "Grep": "read_file",
    "Glob": "read_file",
    "Write": "write_file",
    "Edit": "write_file",
    "NotebookEdit": "write_file",
    "Bash": "shell_execute",
    "WebFetch": "http_request",
    "WebSearch": "browse_url",
    "Agent": "spawn_subagent",
}
#: The two built-in messaging tools deliver to an agent of the same session or to the user's
#: own device: internal, no egress (spec 099, change 4). The list is read off study data.
_INTERNAL_TOOLS: frozenset[str] = frozenset({"SendMessage", "PushNotification"})
INTERNAL = "session_internal"  # a keyword no chain pattern and no role matches

#: LangChain-style tool names -> chain-pattern keyword. Keys are squashed (lowercase,
#: non-alphanumerics removed). The squashed id must equal a key, after an optional
#: ``tool`` prefix and before an optional ``results``/``json`` suffix:
#: ``tool_tavily_search`` and ``TavilySearchResults`` match, while
#: ``shell_execute_tavily_search`` keeps its own words. ``mcp__<server>__<tool>`` ids are
#: never mapped here, because the server name can carry capability words.
_FRAMEWORK_ALIASES: dict[str, str] = {
    "recursiveurlloader": "http_request",
    "tavilysearch": "browse_url",
    "vectorstorequery": "vector_store_read",
    "vectorstoresearch": "vector_store_read",
    # DevOps agent tools (spec 061)
    "readsecrets": "secrets_manager",
    "executecommand": "execute_code",
}

#: Tool ids that grant unscoped shell execution (bare ``Bash`` or ``Bash(*)``).
UNRESTRICTED_EXEC_TOOLS: frozenset[str] = frozenset({"Bash", "Bash(*)"})

#: Verbs that send data to someone other than the user. Creating or updating an object in the
#: user's own account is a write, not egress (spec 099, change 4).
_OUTBOUND_VERBS = frozenset({"send", "post", "reply", "publish"})
#: The keyword of a sink its permission specifier confines to named domains or commands: it
#: matches no chain pattern and has no role (spec 099, change 6).
CONFINED = "confined"
_RULE = re.compile(r"(\w+)\((.*)\)", re.DOTALL)  # permission-rule form "Name(specifier)"
#: A path to a credential file: a permission spec here, a path token in chain_targeting.
SECRET_PATH = re.compile(
    r"(?:^|[/~])\.env\b"
    r"|\.ssh/"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.aws/credentials"
    r"|\.(?:netrc|npmrc|pypirc)\b"
    r"|\.(?:pem|key|p12|pfx)$"
    r"|/etc/shadow\b",
    re.IGNORECASE,
)
_GIT_PUSH = re.compile(r"\bgit\s+push\b")
_TOKEN_SEP = re.compile(r"[_-]+")
_NON_ALNUM = re.compile(r"[\W_]+")
_FRAMEWORK_NAME = re.compile(r"(?:tool)?(.+?)(?:results)?(?:json)?")


def _framework_alias(tool_id: str) -> str:
    """Return the keyword for a LangChain-style tool id, else ``tool_id``."""
    m = _FRAMEWORK_NAME.fullmatch(_NON_ALNUM.sub("", tool_id.lower()))
    return _FRAMEWORK_ALIASES.get(m[1], tool_id) if m else tool_id


def canonical_tool_name(tool_id: str) -> str:
    """Return the chain-pattern keyword for a known tool id, else ``tool_id``."""
    if tool_id.startswith("mcp__"):
        parts = tool_id.split("__", 2)
        if len(parts) == 3:
            server_tokens = set(_TOKEN_SEP.split(parts[1].lower()))
            verb = next(
                (t for t in _TOKEN_SEP.split(parts[2].lower()) if t and t not in server_tokens),
                "",
            )
            if verb in _OUTBOUND_VERBS:
                return "send_email"
        return tool_id

    m = _RULE.fullmatch(tool_id)
    name, spec = (m[1], m[2]) if m else (tool_id, "")
    if name in _INTERNAL_TOOLS:
        return INTERNAL
    canonical = _BUILTIN_ALIASES.get(name)
    if canonical is None:
        return _framework_alias(tool_id)
    if canonical == "read_file" and SECRET_PATH.search(spec):
        return "read_secret_file"
    if name == "Bash" and _GIT_PUSH.search(spec):
        return "git_push"
    if (name == "Bash" and spec.strip(" *:")) or (
        name == "WebFetch" and spec.startswith("domain:") and spec[7:].strip(" *")
    ):
        return CONFINED
    return canonical
