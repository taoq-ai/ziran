"""Claude Code tool-name aliases for chain matching.

This is the single shared Claude Code vocabulary used by chain analysis
(:mod:`ziran.application.knowledge_graph.chain_analyzer`) and trace
analysis (#421). Do not duplicate it elsewhere; import from here, and only
from application-layer code.

:func:`canonical_tool_name` maps a Claude Code tool id (``Read``, ``Bash``,
``mcp__slack__slack_send_message``, ``Read(./.env)`` ...) to the capability
keyword the chain patterns already use. Any other id is returned unchanged,
so matching for non-Claude-Code tools is not affected. The result is for
matching only; node ids and reported findings keep the original names.
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

#: Tool ids that grant unscoped shell execution (bare ``Bash`` or ``Bash(*)``).
UNRESTRICTED_EXEC_TOOLS: frozenset[str] = frozenset({"Bash", "Bash(*)"})

_OUTBOUND_VERBS = frozenset({"send", "post", "create", "reply", "publish", "update"})
_RULE = re.compile(r"(\w+)\((.*)\)", re.DOTALL)  # permission-rule form "Name(specifier)"
_SECRET_PATH = re.compile(
    r"(?:^|[/~])\.env\b"
    r"|\.ssh/"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.aws/credentials"
    r"|\.(?:netrc|npmrc|pypirc)\b"
    r"|\.(?:pem|key|p12|pfx)$",
    re.IGNORECASE,
)
_GIT_PUSH = re.compile(r"\bgit\s+push\b")
_TOKEN_SEP = re.compile(r"[_-]+")


def canonical_tool_name(tool_id: str) -> str:
    """Return the chain-pattern keyword for a Claude Code tool id, else ``tool_id``."""
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
    canonical = _BUILTIN_ALIASES.get(name)
    if canonical is None:
        return tool_id
    if canonical == "read_file" and _SECRET_PATH.search(spec):
        return "read_secret_file"
    if name == "Bash" and _GIT_PUSH.search(spec):
        return "git_push"
    return canonical
