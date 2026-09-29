"""Discover and parse Claude Code plugins, ``.claude/agents`` and bare ``agents/`` directories.

Discovery for ``load_claude_code(path)``:

* ``path`` is a ``.md`` file: parsed as one agent file (root = its parent). Any other file or a
  missing path: empty scan.
* Manifest: ``root/.claude-plugin/plugin.json``.
* Agent sources, in order: ``root/agents``, ``root/.claude/agents``, ``root`` itself when it is
  named ``agents``, then the manifest's ``agents`` paths. Directories contribute sorted ``*.md``
  (non-recursive); duplicates are dropped by resolved path. A ``.md`` file is an agent file only
  when its first line is ``---``; other ``.md`` files are skipped silently.
* Hooks (``root/hooks/hooks.json`` + manifest ``hooks``) and MCP config (``root/.mcp.json`` +
  manifest ``mcpServers``) are read only when a manifest or an agent file exists.

Nothing in a file makes this raise: problems become value-free ``ClaudeCodeParseIssue``s. Never
``model_dump()`` a scan wholesale into a report: ``system_prompt`` and MCP ``url``/``args``/
``command`` (expanded from the environment by the MCP loader) may hold secrets.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import ValidationError

from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent,
    ClaudeCodeHook,
    ClaudeCodeParseIssue,
    ClaudeCodePlugin,
    ClaudeCodeScan,
)
from ziran.infrastructure.config.claude_mcp_config import ClaudeConfigError, load_claude_mcp_config
from ziran.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

MAX_FILE_BYTES: Final = 1_048_576
_AGENT_KEYS = ("name", "description", "tools", "model")


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))  # never raises, even on symlink loops


def _first_error(exc: ValidationError) -> tuple[str, str]:
    """(top-level key, message) of the first error; pydantic inputs are never included."""
    err = exc.errors(include_input=False, include_url=False)[0]
    return str(err["loc"][0]) if err["loc"] else "", err["msg"]


class _Scanner:
    def __init__(self, root: Path, scan: ClaudeCodeScan) -> None:
        self.root = root
        self.base = _real(root)
        self.scan = scan
        self.names: dict[str, ClaudeCodeAgent] = {}

    def issue(self, file: Path, message: str, line: int | None = None) -> None:
        self.scan.issues.append(ClaudeCodeParseIssue(file=str(file), line=line, message=message))

    def read(self, file: Path) -> str | None:
        real = _real(file)
        if not real.is_relative_to(self.base):
            self.issue(file, "file resolves outside the plugin root")
            return None
        try:
            if real.stat().st_size > MAX_FILE_BYTES:
                self.issue(file, f"file is larger than {MAX_FILE_BYTES} bytes")
                return None
            return real.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            self.issue(file, f"cannot read file ({type(exc).__name__})")
            return None

    def read_json(self, file: Path) -> dict[str, Any] | None:
        text = self.read(file)
        if text is None:
            return None
        self.scan.files_analyzed += 1
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.issue(file, "invalid JSON", exc.lineno)
            return None
        if not isinstance(data, dict):
            self.issue(file, "expected a JSON object")
            return None
        return data

    def component_paths(self, manifest: Path, data: dict[str, Any], key: str) -> list[Path]:
        value = data.get(key)
        if value is None:
            return []
        if isinstance(value, dict) and key != "agents":
            logger.debug("claude_code_inline_component_ignored", key=key)
            return []
        items = [value] if isinstance(value, str) else value
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            self.issue(manifest, f"component path '{key}' must be a string or a list of strings")
            return []
        paths: list[Path] = []
        for item in items:
            path = self.root / item
            if not _real(path).is_relative_to(self.base):
                self.issue(manifest, f"component path '{key}' escapes the plugin root")
            elif not os.path.exists(path):
                self.issue(manifest, f"component path '{key}' not found")
            else:
                paths.append(path)
        return paths

    def agent_files(self, sources: list[Path]) -> int:
        """Parse every agent file under *sources*; return how many agent files were found."""
        found = 0
        for file in _unique([f for s in sources for f in _expand(s)]):
            text = self.read(file)
            if text is None:
                continue
            lines = text.splitlines()
            if not lines or lines[0].rstrip() != "---":
                continue
            found += 1
            self.scan.files_analyzed += 1
            self.agent(file, lines)
        return found

    def agent(self, file: Path, lines: list[str]) -> None:
        end = next((i for i in range(1, len(lines)) if lines[i].rstrip() == "---"), None)
        if end is None:
            self.issue(file, "frontmatter is not closed with '---'", 1)
            return
        frontmatter = "\n".join(lines[1:end])
        try:
            data = yaml.safe_load(frontmatter)
            node = yaml.compose(frontmatter, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            # Never str(exc): it embeds the offending source line.
            mark = getattr(exc, "problem_mark", None)
            problem = getattr(exc, "problem", None) or "syntax error"
            self.issue(file, f"invalid YAML frontmatter: {problem}", mark.line + 2 if mark else 2)
            return
        if data is None:
            data = {}
        if not isinstance(data, dict):
            self.issue(file, "frontmatter must be a YAML mapping", 2)
            return
        key_lines = (
            {str(k.value): k.start_mark.line + 2 for k, _ in node.value}
            if isinstance(node, yaml.MappingNode)
            else {}
        )
        fields = {k: data[k] for k in _AGENT_KEYS if k in data}
        try:
            agent = ClaudeCodeAgent.model_validate(
                fields
                | {
                    "file": str(file),
                    "key_lines": key_lines,
                    "system_prompt": "\n".join(lines[end + 1 :]),
                    "body_line": end + 2,
                }
            )
        except ValidationError as exc:
            key, msg = _first_error(exc)
            self.issue(file, f"invalid frontmatter field '{key}': {msg}", key_lines.get(key, 1))
            return
        first = self.names.get(agent.name)
        if first is not None:
            self.issue(
                file,
                f"duplicate agent name '{agent.name}' (first defined in {first.file})",
                agent.line_of("name"),
            )
            return
        self.names[agent.name] = agent
        self.scan.agents.append(agent)

    def plugin(self, file: Path, data: dict[str, Any]) -> None:
        fields = {k: data[k] for k in ("name", "version", "description") if k in data}
        try:
            self.scan.plugin = ClaudeCodePlugin.model_validate(fields | {"file": str(file)})
        except ValidationError as exc:
            key, msg = _first_error(exc)
            self.issue(file, f"invalid plugin.json field '{key}': {msg}")

    def hooks(self, file: Path) -> None:
        data = self.read_json(file)
        if data is None:
            return
        events = data.get("hooks")
        if not isinstance(events, dict):
            self.issue(file, "expected a 'hooks' object")
            return
        for event, groups in events.items():
            for group in groups if isinstance(groups, list) else [None]:
                entries = group.get("hooks") if isinstance(group, dict) else None
                for hook in entries if isinstance(entries, list) else [None]:
                    try:
                        if not isinstance(hook, dict) or not isinstance(group, dict):
                            raise ValueError
                        self.scan.hooks.append(
                            ClaudeCodeHook.model_validate(
                                {
                                    "event": event,
                                    "matcher": group.get("matcher"),
                                    "type": hook.get("type"),
                                    "command": hook.get("command"),
                                    "file": str(file),
                                }
                            )
                        )
                    except ValueError:  # includes pydantic ValidationError
                        self.issue(file, f"malformed hook entry for event '{event}'")

    def mcp(self, file: Path) -> None:
        if self.read(file) is None:  # containment and size check before the loader reads it
            return
        self.scan.files_analyzed += 1
        try:
            self.scan.mcp_servers.extend(load_claude_mcp_config(file))
        except (ClaudeConfigError, OSError) as exc:
            self.issue(file, str(exc))


def _expand(source: Path) -> list[Path]:
    """Sorted ``*.md`` of a directory (non-recursive); a file is itself."""
    return sorted(source.glob("*.md")) if os.path.isdir(source) else [source]


def _unique(paths: list[Path]) -> list[Path]:
    """Existing paths (os.path never raises), de-duplicated by resolved path, first occurrence kept."""
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        real = _real(path)
        if real not in seen and os.path.exists(path):
            seen.add(real)
            out.append(path)
    return out


def load_claude_code(path: Path) -> ClaudeCodeScan:
    """Discover and parse Claude Code agent definitions under *path*.

    Never raises for file content, missing or unreadable files; problems are returned in
    ``scan.issues``.
    """
    scan = ClaudeCodeScan(root=str(path))
    if os.path.isfile(path):
        if path.suffix == ".md":
            _Scanner(path.parent, scan).agent_files([path])
        return scan
    if not os.path.isdir(path):
        return scan

    scanner = _Scanner(path, scan)
    manifest = path / ".claude-plugin" / "plugin.json"
    data = scanner.read_json(manifest) if os.path.isfile(manifest) else None
    if data is not None:
        scanner.plugin(manifest, data)

    def component(key: str) -> list[Path]:
        return scanner.component_paths(manifest, data, key) if data is not None else []

    sources = [path / "agents", path / ".claude" / "agents"]
    if path.name == "agents":
        sources.append(path)
    found = scanner.agent_files([*sources, *component("agents")])
    if not os.path.isfile(manifest) and not found:
        return scan

    for file in _unique([path / "hooks" / "hooks.json", *component("hooks")]):
        scanner.hooks(file)
    for file in _unique([path / ".mcp.json", *component("mcpServers")]):
        scanner.mcp(file)
    return scan
