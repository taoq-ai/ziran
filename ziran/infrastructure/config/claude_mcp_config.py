"""Load MCP servers from Claude Code configuration files.

Accepts a project ``.mcp.json`` (``{"mcpServers": {...}}``), a plugin
``.mcp.json`` (flat ``{name: server}`` map) and user settings JSON (top-level
``mcpServers`` next to unrelated keys). ``env`` and ``headers`` values are kept
as ``SecretStr`` on :class:`ServerEntry` and never logged or echoed in errors:
only their key names are.
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ziran.domain.entities.registry import ServerEntry
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_ENTRY_FIELDS = ("url", "command", "args", "env", "headers")


class ClaudeConfigError(ValueError):
    """Raised when a Claude Code MCP config cannot be used. Never echoes config values."""


def _expand(value: Any, env: dict[str, str]) -> Any:
    """Expand ``${VAR}`` / ``${VAR:-default}`` in every string; unset without default stays literal."""
    if isinstance(value, str):
        return _PLACEHOLDER.sub(
            lambda m: env.get(m.group(1), m.group(0) if m.group(2) is None else m.group(2)), value
        )
    if isinstance(value, list):
        return [_expand(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, env) for k, v in value.items()}
    return value


def _transport(entry: dict[str, Any]) -> str | None:
    kind = entry.get("type")
    if kind == "sse" and "url" in entry:
        return "sse"
    if kind in (None, "stdio") and "command" in entry:
        return "stdio"
    if kind in (None, "http") and "url" in entry:
        return "streamable-http"
    return None


def load_claude_mcp_config(path: Path) -> list[ServerEntry]:
    """Parse a Claude Code MCP config into :class:`ServerEntry` objects.

    Raises:
        ClaudeConfigError: invalid JSON, no servers, or an unusable server entry.
        OSError: the file cannot be read.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClaudeConfigError(f"{path}: invalid JSON at line {exc.lineno}") from None
    if not isinstance(data, dict):
        raise ClaudeConfigError(f"{path}: expected a JSON object")

    servers = data.get("mcpServers", data)
    if (
        not isinstance(servers, dict)
        or not servers
        or not all(isinstance(v, dict) for v in servers.values())
    ):
        raise ClaudeConfigError(f"{path}: no mcpServers found")

    env_map = {"CLAUDE_PLUGIN_ROOT": str(path.parent.resolve()), **os.environ}
    entries: list[ServerEntry] = []
    for name, raw in servers.items():
        entry = _expand(raw, env_map)
        transport = _transport(entry)
        if transport is None:
            raise ClaudeConfigError(
                f"{path}: server '{name}': unsupported type or missing 'command'/'url'"
            )
        try:
            server = ServerEntry(
                name=name,
                transport=transport,
                **{k: entry[k] for k in _ENTRY_FIELDS if k in entry},
            )
        except ValidationError as exc:
            # Never str(exc): pydantic's default rendering includes input values.
            detail = "; ".join(
                f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                for e in exc.errors(include_input=False, include_url=False)
            )
            raise ClaudeConfigError(f"{path}: server '{name}': {detail}") from None
        logger.info(
            "claude_mcp_server_loaded",
            server=name,
            transport=transport,
            env_keys=sorted(server.env),
            header_keys=sorted(server.headers),
        )
        entries.append(server)
    return entries
