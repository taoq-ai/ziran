"""Unit tests for the Claude Code MCP config loader."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
import structlog
from structlog.testing import capture_logs

from ziran.infrastructure.config import claude_mcp_config
from ziran.infrastructure.config.claude_mcp_config import (
    ClaudeConfigError,
    load_claude_mcp_config,
)

if TYPE_CHECKING:
    from pathlib import Path

_SERVERS: dict[str, Any] = {
    "local": {"command": "python", "args": ["srv.py", "--flag"], "env": {"TOKEN": "s3cret-env"}},
    "remote": {
        "type": "http",
        "url": "https://mcp.example.com/mcp",
        "headers": {"Authorization": "Bearer s3cret-hdr"},
    },
}


def _write(tmp_path: Path, data: Any, name: str = ".mcp.json") -> Path:
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.unit
class TestShapes:
    def test_project_form(self, tmp_path: Path) -> None:
        servers = load_claude_mcp_config(_write(tmp_path, {"mcpServers": _SERVERS}))
        by_name = {s.name: s for s in servers}
        assert by_name["local"].transport == "stdio"
        assert by_name["local"].command == "python"
        assert by_name["local"].args == ["srv.py", "--flag"]
        assert by_name["local"].url is None
        assert by_name["remote"].transport == "streamable-http"
        assert by_name["remote"].url == "https://mcp.example.com/mcp"
        assert by_name["remote"].command is None

    def test_plugin_flat_form(self, tmp_path: Path) -> None:
        flat = load_claude_mcp_config(_write(tmp_path, _SERVERS))
        nested = load_claude_mcp_config(_write(tmp_path, {"mcpServers": _SERVERS}, "b.json"))
        assert [s.model_dump() for s in flat] == [s.model_dump() for s in nested]

    def test_user_settings_ignores_unrelated_keys(self, tmp_path: Path) -> None:
        data = {"theme": "dark", "permissions": {"allow": []}, "mcpServers": _SERVERS}
        servers = load_claude_mcp_config(_write(tmp_path, data))
        assert sorted(s.name for s in servers) == ["local", "remote"]

    def test_sse_and_explicit_stdio(self, tmp_path: Path) -> None:
        data = {
            "a": {"type": "sse", "url": "https://x.example.com/sse"},
            "b": {"type": "stdio", "command": "node"},
            "c": {"url": "https://y.example.com/mcp"},
        }
        by_name = {s.name: s for s in load_claude_mcp_config(_write(tmp_path, data))}
        assert by_name["a"].transport == "sse"
        assert by_name["b"].transport == "stdio"
        assert by_name["c"].transport == "streamable-http"


@pytest.mark.unit
class TestExpansion:
    def test_placeholders(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZIRAN_T_HOST", "mcp.example.com")
        monkeypatch.delenv("ZIRAN_T_UNSET", raising=False)
        data = {
            "s": {
                "command": "${ZIRAN_T_BIN:-python}",
                "args": ["${CLAUDE_PLUGIN_ROOT}/srv.py", "${ZIRAN_T_UNSET}"],
                "env": {"HOST": "${ZIRAN_T_HOST}"},
            },
            "h": {"url": "https://${ZIRAN_T_HOST}/mcp"},
        }
        path = _write(tmp_path, data)
        by_name = {s.name: s for s in load_claude_mcp_config(path)}
        assert by_name["s"].command == "python"
        assert by_name["s"].args == [f"{tmp_path.resolve()}/srv.py", "${ZIRAN_T_UNSET}"]
        assert by_name["s"].env["HOST"].get_secret_value() == "mcp.example.com"
        assert by_name["h"].url == "https://mcp.example.com/mcp"

    def test_explicit_plugin_root_env_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/plugins/x")
        path = _write(tmp_path, {"s": {"command": "${CLAUDE_PLUGIN_ROOT}/bin"}})
        assert load_claude_mcp_config(path)[0].command == "/plugins/x/bin"


@pytest.mark.unit
class TestSecrets:
    def test_values_not_serialised(self, tmp_path: Path) -> None:
        servers = load_claude_mcp_config(_write(tmp_path, {"mcpServers": _SERVERS}))
        by_name = {s.name: s for s in servers}
        assert by_name["local"].env["TOKEN"].get_secret_value() == "s3cret-env"
        assert by_name["remote"].headers["Authorization"].get_secret_value() == "Bearer s3cret-hdr"
        for s in servers:
            assert "s3cret" not in s.model_dump_json()
            assert "s3cret" not in repr(s)

    def test_log_event_has_key_names_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fresh proxy: the module logger may be cached by an earlier setup_logging().
        monkeypatch.setattr(claude_mcp_config, "logger", structlog.get_logger())
        with capture_logs() as logs:
            load_claude_mcp_config(_write(tmp_path, {"mcpServers": _SERVERS}))
        events = [e for e in logs if e["event"] == "claude_mcp_server_loaded"]
        assert len(events) == 2
        by_name = {e["server"]: e for e in events}
        assert by_name["local"]["env_keys"] == ["TOKEN"]
        assert by_name["remote"]["header_keys"] == ["Authorization"]
        assert "s3cret" not in repr(logs)


@pytest.mark.unit
class TestErrors:
    @pytest.mark.parametrize(
        "data",
        [
            "{not json s3cret",
            "[1, 2]",
            {},
            {"mcpServers": {}},
            {"mcpServers": {"s": "s3cret"}},
            {"s": {"env": {"K": "s3cret"}}},
            {"s": {"type": "s3cret-transport", "url": "https://x.example.com"}},
            {"s": {"type": "http", "command": "s3cret-cmd"}},
            {"s": {"command": "python", "env": {"K": 12345}, "headers": {"H": "s3cret"}}},
            {"s": {"command": "python", "args": "s3cret"}},
        ],
    )
    def test_invalid_config_raises_without_echoing_values(self, tmp_path: Path, data: Any) -> None:
        with pytest.raises(ClaudeConfigError) as exc_info:
            load_claude_mcp_config(_write(tmp_path, data))
        message = str(exc_info.value)
        assert "s3cret" not in message
        assert "12345" not in message
        assert exc_info.value.__cause__ is None or "s3cret" not in str(exc_info.value.__cause__)
