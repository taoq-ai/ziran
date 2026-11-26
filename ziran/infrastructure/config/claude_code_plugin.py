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
import stat
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import ValidationError

from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent,
    ClaudeCodeHook,
    ClaudeCodeParseIssue,
    ClaudeCodePlugin,
    ClaudeCodeScan,
    ClaudeCodeSkill,
    ClaudeCodeSkillFile,
)
from ziran.infrastructure.config.claude_mcp_config import ClaudeConfigError, load_claude_mcp_config
from ziran.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

MAX_FILE_BYTES: Final = 1_048_576
_AGENT_KEYS = ("name", "description", "tools", "model")
MAX_SKILL_FILES: Final = 1000
MAX_SKILL_DEPTH: Final = 8
_OUTSIDE = "file resolves outside the plugin root"
#: suffixes of scripts ZIRAN does not analyse (Python is the one language it reads).
_SCRIPT_SUFFIXES: Final = frozenset(
    {".sh", ".bash", ".zsh", ".fish", ".ksh", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts"}
    | {".cts", ".tsx", ".rb", ".pl", ".pm", ".php", ".ps1", ".psm1", ".bat", ".cmd", ".lua"}
    | {".r", ".pyw"}
)


def _split_tools(text: str) -> list[str]:
    """A tool list split at commas and at spaces, never inside "(...)" (spec 099).

    One pass: a file is untrusted and may hold a tools line of 1 MiB, so no regex lookahead.
    A bracket that is never closed must not swallow the tools after it: the rest of the line,
    from the entry that opened it, is split at its commas, so the audit still sees each tool.
    """
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)  # a stray ")" closes nothing
        elif depth == 0 and (ch == "," or ch.isspace()):
            out.append(text[start:i])
            start = i + 1
    tail = text[start:]
    return [*out, *(tail.split(",") if depth else [tail])]


def _tool_list(value: object) -> object:
    """A ``tools`` value as a list of entries; any other shape is left for the model to refuse."""
    entries = [value] if isinstance(value, str) else value
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        return value
    return [t for e in entries for t in _split_tools(e)]


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
            self.issue(file, _OUTSIDE)
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
        except RecursionError:
            self.issue(file, "JSON is nested too deeply")
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

    def frontmatter(
        self, file: Path, lines: list[str], prefix: str = ""
    ) -> tuple[dict[str, Any], dict[str, int], int] | None:
        """(data, key lines, closing line index) of a ``---`` block, or None after an issue."""
        end = next((i for i in range(1, len(lines)) if lines[i].rstrip() == "---"), None)
        if end is None:
            self.issue(file, f"{prefix}frontmatter is not closed with '---'", 1)
            return None
        frontmatter = "\n".join(lines[1:end])
        try:
            data = yaml.safe_load(frontmatter)
            node = yaml.compose(frontmatter, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            # Never str(exc): it embeds the offending source line.
            mark = getattr(exc, "problem_mark", None)
            problem = getattr(exc, "problem", None) or "syntax error"
            line = mark.line + 2 if mark else 2
            self.issue(file, f"{prefix}invalid YAML frontmatter: {problem}", line)
            return None
        except RecursionError:
            self.issue(file, f"{prefix}frontmatter is nested too deeply", 2)
            return None
        if data is None:
            data = {}
        if not isinstance(data, dict):
            self.issue(file, f"{prefix}frontmatter must be a YAML mapping", 2)
            return None
        key_lines = (
            {str(k.value): k.start_mark.line + 2 for k, _ in node.value}
            if isinstance(node, yaml.MappingNode)
            else {}
        )
        return data, key_lines, end

    def agent(self, file: Path, lines: list[str]) -> None:
        parsed = self.frontmatter(file, lines)
        if parsed is None:
            return
        data, key_lines, end = parsed
        fields = {k: data[k] for k in _AGENT_KEYS if k in data}
        if "tools" not in data and "allowed-tools" in data:  # the key skills and commands use
            fields["tools"] = data["allowed-tools"]
            if "allowed-tools" in key_lines:
                key_lines["tools"] = key_lines["allowed-tools"]
        if "tools" in fields:
            fields["tools"] = _tool_list(fields["tools"])
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

    def skill_files(self, files: list[Path]) -> int:
        """Parse every ``SKILL.md`` in *files* that opens with ``---``; return how many."""
        found = 0
        for file in _unique(files):
            text = self.read(file)
            if text is None:
                continue
            lines = text.splitlines()
            if not lines or lines[0].rstrip() != "---":
                continue
            found += 1
            self.scan.files_analyzed += 1
            self.skill(file, lines)
        return found

    def skill(self, file: Path, lines: list[str]) -> None:
        folder = file.parent
        prefix = f"skill '{folder.name}': "
        parsed = self.frontmatter(file, lines, prefix)
        if parsed is None:
            return
        data, key_lines, end = parsed
        fields = {k: data[k] for k in ("name", "description", "model") if k in data}
        if fields.get("name") is None:
            fields["name"] = folder.name
        if "allowed-tools" in data:
            fields["tools"] = _tool_list(data["allowed-tools"])
            if "allowed-tools" in key_lines:
                key_lines["tools"] = key_lines["allowed-tools"]
        try:
            skill = ClaudeCodeSkill.model_validate(
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
            line = key_lines.get(key, 1)
            self.issue(file, f"{prefix}invalid frontmatter field '{key}': {msg}", line)
            return
        skill.bundled = self.bundled(folder, file)
        self.scan.skills.append(skill)

    def bundled(self, folder: Path, skill_md: Path) -> list[ClaudeCodeSkillFile]:
        """Every file under *folder* but *skill_md*: symlinked folders not followed, bounded."""
        out: list[ClaudeCodeSkillFile] = []
        top = len(folder.parts)
        for dirpath, dirnames, filenames in os.walk(folder):
            here = Path(dirpath)
            for name in sorted(dirnames):
                sub = here / name
                if os.path.islink(sub):
                    dirnames.remove(name)
                    inside = _real(sub).is_relative_to(self.base)
                    self.issue(sub, "symlinked directory is not followed" if inside else _OUTSIDE)
            dirnames.sort()
            if dirnames and len(here.parts) - top >= MAX_SKILL_DEPTH:
                self.issue(
                    here, f"folders nested deeper than {MAX_SKILL_DEPTH} levels are not read"
                )
                dirnames.clear()
            for name in sorted(filenames):
                file = here / name
                if file == skill_md:
                    continue
                if len(out) == MAX_SKILL_FILES:
                    self.issue(
                        folder, f"more than {MAX_SKILL_FILES} bundled files; the rest are not read"
                    )
                    return out
                entry = self.bundled_file(file)
                if entry is not None:
                    out.append(entry)
        return out

    def bundled_file(self, file: Path) -> ClaudeCodeSkillFile | None:
        real = _real(file)
        if not real.is_relative_to(self.base):
            self.issue(file, _OUTSIDE)
            return None
        kind: Literal["python", "script", "other"]
        try:
            st = os.stat(real)
            if not stat.S_ISREG(st.st_mode):  # never open a FIFO or device
                self.issue(file, "not a regular file")
                return None
            if file.suffix == ".py":
                if st.st_size > MAX_FILE_BYTES:
                    self.issue(file, f"file is larger than {MAX_FILE_BYTES} bytes")
                    return None
                kind = "python"
            elif file.suffix.lower() in _SCRIPT_SUFFIXES or st.st_mode & 0o111:
                kind = "script"
            else:
                with open(real, "rb") as fh:
                    kind = "script" if fh.read(2) == b"#!" else "other"
        except OSError as exc:
            self.issue(file, f"cannot read file ({type(exc).__name__})")
            return None
        return ClaudeCodeSkillFile(path=str(file), kind=kind)

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
            servers = load_claude_mcp_config(file, expand_env=False)
        except (ClaudeConfigError, OSError) as exc:
            self.issue(file, str(exc))
            return
        self.scan.mcp_servers.extend(servers)
        for server in servers:
            self.scan.mcp_sources.setdefault(server.name, str(file))


def _expand(source: Path) -> list[Path]:
    """Sorted ``*.md`` of a directory (non-recursive); a file is itself."""
    return sorted(source.glob("*.md")) if os.path.isdir(source) else [source]


def _skill_md(source: Path) -> list[Path]:
    """``SKILL.md`` files of a source: the file itself, a skill folder, or a folder of them."""
    if source.name == "SKILL.md":
        return [source]
    if os.path.isfile(source / "SKILL.md"):
        return [source / "SKILL.md"]
    return sorted(source.glob("*/SKILL.md")) if os.path.isdir(source) else []


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
        if path.name == "SKILL.md":
            _Scanner(path.parent, scan).skill_files([path])
        elif path.suffix == ".md":
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
    skill_sources = [path / "skills", path / ".claude" / "skills", *component("skills")]
    if path.name == "skills":
        skill_sources.append(path)
    skill_md = [path / "SKILL.md", *(f for s in skill_sources for f in _skill_md(s))]
    found += scanner.skill_files(skill_md)
    if not os.path.isfile(manifest) and not found:
        return scan

    for file in _unique([path / "hooks" / "hooks.json", *component("hooks")]):
        scanner.hooks(file)
    for file in _unique([path / ".mcp.json", *component("mcpServers")]):
        scanner.mcp(file)
    return scan
