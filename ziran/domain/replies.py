"""Replies that are not an agent's answer, shared by adapters and attack executors."""

from __future__ import annotations

#: What an MCP handler returns when the server takes no chat prompt (spec 082).
NO_CHAT_REPLY = "[MCP server does not support direct messaging — use tools/call]"

#: Framework error phrases (LangChain iteration and time limits), matched as substrings.
ERROR_SENTINELS: frozenset[str] = frozenset(
    {
        "agent stopped due to iteration limit",
        "agent stopped due to max iterations",
        "agent stopped due to time limit",
    }
)


def is_no_chat_reply(text: str) -> bool:
    """True only for the exact placeholder: a target cannot hide a finding by quoting it."""
    return text.strip() == NO_CHAT_REPLY


def is_error_response(text: str) -> bool:
    """Return *True* when *text* is a framework error or the no-chat placeholder rather
    than a genuine agent answer, so it never counts as a reply.
    """
    text_lower = text.strip().lower().rstrip(".")
    return is_no_chat_reply(text) or any(s in text_lower for s in ERROR_SENTINELS)
