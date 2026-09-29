# Implementation Plan: Parse Claude Code plugin manifests and subagent files into capabilities

**Branch**: `037-claude-code-plugin-parser` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #416 (epic #415) | **Consumers**: #418, #419, #420 build against §Public contract in
parallel; WUWEI #36 pins the release.

## Summary
Add one domain module with the Claude Code models and tool vocabulary
(`ziran/domain/entities/claude_code.py`) and one infrastructure module that discovers and parses a
plugin / `.claude/agents` / bare `agents/` directory into those models
(`ziran/infrastructure/config/claude_code_plugin.py`). No CLI, no JSON output, no exit codes in
this issue: `ziran audit` wiring is #418. Problems in files are returned as value-free
`ClaudeCodeParseIssue`s with file and line; the parser never raises for file content.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (models), PyYAML `safe_load`/`compose` (frontmatter), stdlib `json`/`re`/`pathlib`; reuses `load_claude_mcp_config` (#422) and `ziran.domain.tool_classifier.is_dangerous`. No new dependencies.
**Storage**: N/A — reads plugin files only.
**Testing**: pytest; `@pytest.mark.unit` (entities, parser on `tmp_path`), `@pytest.mark.integration`
(parser over the committed fixture plugins). No network, no LLM.
**Target Platform**: library code consumed by the `ziran audit` CLI (#418).
**Project Type**: single Python package (`ziran/`)
**Performance Goals**: linear in the number of files; each file read once; 1 MiB per-file cap.
**Constraints**: mypy strict; line length 100; infrastructure must not import `ziran.application`.
**Scale/Scope**: 2 new source files, 2 new test files, 3 fixture directories (~12 small files).

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Models + vocabulary in `domain/entities/claude_code.py` (imports only `domain`: `capability`, `registry`, `tool_classifier`). File discovery/parsing in `infrastructure/config/claude_code_plugin.py` (imports domain + sibling `claude_mcp_config`; never `ziran.application`). Application consumers (#418 chain analysis, #419 baseline) import only the domain models; the CLI (interfaces) calls the parser. The #417 alias map stays in `application/` and is not imported (chain matching applies it later, in `ToolChainAnalyzer`). |
| II. Type safety | PASS | Every structure is a Pydantic model; all functions annotated; mypy strict. |
| III. Tests | PASS | Test-first per task; unit tests for entities and parser edge cases; integration tests over committed fixture plugins (issue acceptance). |
| IV. Async-first | PASS (justified) | Local file parsing is synchronous, like `StaticAnalyzer.analyze_file` and `load_claude_mcp_config`, which the sync `ziran audit` entry point already calls. No network I/O. Making it async would force `asyncio.run` into the audit CLI for no concurrency gain. |
| V. Extensibility | PASS | No new port; a new input format behind one function. |
| VI. Simplicity | PASS | One public function, five small models, one vocabulary table. No package, no base class, no lenient YAML fallback, no inline-object support (recorded as ceilings). |

No violations; Complexity Tracking not needed.

## Public contract

This section is binding for #416's implementer and for #418/#419/#420, which are implemented in
parallel before this code exists. Names, signatures and semantics MUST NOT change without updating
this file.

### A. `ziran/domain/entities/claude_code.py` (new)

```python
from typing import Final
from pydantic import BaseModel, Field, field_validator
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.registry import ServerEntry
from ziran.domain.tool_classifier import is_dangerous

#: name -> (capability type, dangerous, requires_permission). Insertion order is the
#: "unrestricted" tool set (effective_tools of an agent without a `tools` key).
CLAUDE_CODE_BUILTIN_TOOLS: Final[dict[str, tuple[CapabilityType, bool, bool]]] = {
    "Agent":        (CapabilityType.TOOL,         True,  False),
    "Bash":         (CapabilityType.TOOL,         True,  True),
    "Edit":         (CapabilityType.DATA_ACCESS,  True,  True),
    "Glob":         (CapabilityType.DATA_ACCESS,  False, False),
    "Grep":         (CapabilityType.DATA_ACCESS,  False, False),
    "NotebookEdit": (CapabilityType.DATA_ACCESS,  True,  True),
    "Read":         (CapabilityType.DATA_ACCESS,  False, False),
    "Skill":        (CapabilityType.SKILL,        False, True),
    "TodoWrite":    (CapabilityType.TOOL,         False, False),
    "WebFetch":     (CapabilityType.EXTERNAL_API, True,  True),
    "WebSearch":    (CapabilityType.EXTERNAL_API, False, True),
    "Write":        (CapabilityType.DATA_ACCESS,  True,  True),
}

def claude_code_tool_capability(tool: str) -> AgentCapability:
    """AgentCapability for one declared Claude Code tool string (kept verbatim as id and name).

    base = tool.split("(", 1)[0]
    - base in CLAUDE_CODE_BUILTIN_TOOLS -> that row          (so "Bash(npm test:*)" -> Bash row)
    - tool.startswith("mcp__")          -> (EXTERNAL_API, is_dangerous(tool), True)
    - otherwise                         -> (TOOL,         is_dangerous(tool), False)
    returns AgentCapability(id=tool, name=tool, type=..., dangerous=..., requires_permission=...)
    """

class ClaudeCodeParseIssue(BaseModel):
    file: str               # path string as discovered (same spelling as ClaudeCodeAgent.file)
    line: int | None = None # 1-based; None when the problem has no line (unreadable file, path escape)
    message: str            # value-free: key names and error kinds only, never file content

class ClaudeCodeAgent(BaseModel):
    name: str = Field(min_length=1)          # frontmatter `name` (required)
    description: str = ""                    # frontmatter `description`
    tools: list[str] | None = None           # declared, verbatim; None = unrestricted
    model: str | None = None                 # frontmatter `model` (e.g. "sonnet", "inherit")
    file: str                                # agent file path string
    key_lines: dict[str, int] = Field(default_factory=dict)  # top-level frontmatter key -> 1-based line
    system_prompt: str = ""                  # markdown body after the closing '---'
    body_line: int = Field(ge=1)             # 1-based line of the first body line

    @field_validator("tools", mode="before")
    @classmethod
    def _normalise_tools(cls, value: object) -> object:
        # None / "" / whitespace / []                     -> None
        # str  -> re.split(r",\s*(?![^()]*\))", value)     (commas inside (...) are kept)
        # list -> as is; any non-str item -> raise ValueError("tools entries must be strings")
        # then: strip each, drop empty, de-duplicate keeping first occurrence;
        #       an empty result -> None
        # any other type is returned unchanged so pydantic rejects it (list_type error)

    @property
    def unrestricted(self) -> bool: ...          # self.tools is None
    @property
    def effective_tools(self) -> list[str]: ...  # list(self.tools) or list(CLAUDE_CODE_BUILTIN_TOOLS)
    @property
    def capabilities(self) -> list[AgentCapability]: ...  # [claude_code_tool_capability(t) for t in effective_tools]
    def line_of(self, key: str) -> int: ...      # self.key_lines.get(key, 1)

class ClaudeCodeHook(BaseModel):
    event: str               # e.g. "PreToolUse", "PostToolUse", "SessionStart"
    matcher: str | None = None
    type: str                # "command" | "prompt" | ... (verbatim)
    command: str | None = None
    file: str                # hooks.json path string

class ClaudeCodePlugin(BaseModel):
    name: str = Field(min_length=1)
    version: str | None = None
    description: str | None = None
    file: str                # plugin.json path string

class ClaudeCodeScan(BaseModel):
    root: str                                    # str(path) as passed to load_claude_code
    plugin: ClaudeCodePlugin | None = None
    agents: list[ClaudeCodeAgent] = Field(default_factory=list)
    hooks: list[ClaudeCodeHook] = Field(default_factory=list)
    mcp_servers: list[ServerEntry] = Field(default_factory=list)
    issues: list[ClaudeCodeParseIssue] = Field(default_factory=list)
    files_analyzed: int = 0                      # agent files + manifest + hooks + mcp files read

    @property
    def detected(self) -> bool: ...  # plugin is not None or bool(agents) or bool(issues)
```

Model rules: pydantic defaults (`extra="ignore"`), not frozen. No field aliases: frontmatter keys
`name`, `description`, `tools`, `model` map 1:1 to fields, so a validation error's `loc[0]` is the
frontmatter key (used for `line_of`).

### B. `ziran/infrastructure/config/claude_code_plugin.py` (new)

```python
MAX_FILE_BYTES: Final = 1_048_576

def load_claude_code(path: Path) -> ClaudeCodeScan:
    """Discover and parse Claude Code agent definitions under *path*. Never raises for file
    content, missing or unreadable files; problems are returned in ``scan.issues``."""
```

**Discovery** (`root` = `path` if it is a directory; for a file see step 1):
1. `path` is a file: if its suffix is `.md`, parse it as one agent file with `root = path.parent`;
   otherwise return the empty scan. `path` neither file nor directory: empty scan.
2. Manifest: `root/.claude-plugin/plugin.json` if it is a file.
3. Agent sources, in this order: `root/agents`, `root/.claude/agents`, `root` itself when
   `root.name == "agents"`, then every `agents` path from the manifest. A directory source
   contributes `sorted(dir.glob("*.md"))` (non-recursive); a file source contributes itself.
   Candidates are de-duplicated by resolved path, first occurrence kept.
4. A candidate is an **agent file** iff its first line (after an optional UTF-8 BOM, `rstrip()`ed)
   is `---`. Other `.md` files are skipped silently and not counted.
5. If there is no manifest and no agent file: return the scan (not `detected`); hooks and MCP files
   are NOT read.
6. Hooks: `root/hooks/hooks.json` if it is a file, then manifest `hooks` paths. MCP:
   `root/.mcp.json` if it is a file, then manifest `mcpServers` paths. De-duplicated by resolved
   path.

**Manifest component paths** (`agents`, `hooks`, `mcpServers`): a string or a list of strings,
each relative to `root`. Issue (file = manifest, line = None) and skip when a value has any other
type — except a JSON object for `hooks` / `mcpServers` (inline config), which is ignored with a
`logger.debug` and no issue. Issue and skip when a path resolves outside `root.resolve()`
(`"component path '<key>' escapes the plugin root"`) or does not exist
(`"component path '<key>' not found"`). The path string itself is not echoed.

**Reading** (one private helper used for every file): issue + skip when the resolved file is
outside `root.resolve()`, larger than `MAX_FILE_BYTES`, or raises `OSError` /
`UnicodeDecodeError`. Encoding `utf-8-sig`. `files_analyzed` counts every successfully read
manifest, hooks and MCP file and every agent file (step 4: a `.md` without the opening fence is
read but not counted). A file that fails the read helper is not counted.

**Agent file parsing**:
- `lines = text.splitlines()`; closing fence = first `i >= 1` with `lines[i].rstrip() == "---"`;
  none -> issue `line=1`, `"frontmatter is not closed with '---'"`.
- `fm = "\n".join(lines[1:i])`; `data = yaml.safe_load(fm)`; `node = yaml.compose(fm,
  Loader=yaml.SafeLoader)`. `yaml.YAMLError` -> issue with
  `line = exc.problem_mark.line + 2` when a mark exists (else `2`),
  `message = f"invalid YAML frontmatter: {exc.problem}"` (`problem` only; `str(exc)` embeds the
  source line and is forbidden).
- `data is None` -> `{}`; not a `dict` -> issue `line=2`, `"frontmatter must be a YAML mapping"`.
- `key_lines = {str(k.value): k.start_mark.line + 2 for k, _ in node.value}` when `node` is a
  `yaml.MappingNode`, else `{}` (`compose` returns `None` for empty frontmatter).
- `system_prompt = "\n".join(lines[i + 1:])`, `body_line = i + 2`.
- `ClaudeCodeAgent.model_validate({k: data[k] for k in ("name", "description", "tools", "model")
  if k in data} | {"file": str(file), "key_lines": ..., "system_prompt": ..., "body_line": ...})`.
  `ValidationError` -> one issue for the first error:
  `key = str(err["loc"][0])`, `line = key_lines.get(key, 1)`,
  `message = f"invalid frontmatter field '{key}': {err['msg']}"` using
  `exc.errors(include_input=False, include_url=False)`.
- Duplicate `name` (already parsed in this scan): issue at `line_of("name")`,
  `f"duplicate agent name '{name}' (first defined in {first.file})"`; agent not added.

**plugin.json / hooks.json**: `json.loads`; `JSONDecodeError` -> issue `line=exc.lineno`,
`"invalid JSON"`. Non-object -> issue `line=None`, `"expected a JSON object"`.
- plugin.json -> `ClaudeCodePlugin.model_validate({k: data[k] for k in ("name", "version",
  "description") if k in data} | {"file": str(file)})`; `ValidationError` -> issue
  `f"invalid plugin.json field '{key}': {msg}"`, `plugin` stays `None`, discovery continues
  (agents are still audited).
- hooks.json -> `data["hooks"]` must be an object of `event -> list[group]`; each group an object
  with optional `matcher` and a `hooks` list; each hook an object -> `ClaudeCodeHook.model_validate(
  {"event": event, "matcher": group.get("matcher"), "type": hook.get("type"),
  "command": hook.get("command"), "file": str(file)})`. Any shape or validation problem -> issue
  `line=None`, `f"malformed hook entry for event '{event}'"` (or `"expected a 'hooks' object"`),
  skip that entry, continue.

**MCP**: `load_claude_mcp_config(file)` (existing, unchanged) -> `scan.mcp_servers.extend(...)`;
`ClaudeConfigError` / `OSError` -> issue `line=None`, `message=str(exc)` (the loader's messages
never contain config values). The containment/size check of the read helper runs first.

**Ordering**: `agents` in discovery order (source order, then sorted file name); `hooks` in file
order then JSON order; `issues` in the order encountered.

### C. Guidance for consumers (#418 / #419 / #420)

Binding for this issue only in the sense that the fields above support it; #418/#419 own their
CLI flags, rule ids and JSON.
- **Detection**: `scan = load_claude_code(Path(PATH))`; `scan.detected` tells whether PATH holds
  Claude Code definitions. A pure Python project returns `detected is False` and no issues, so the
  existing `*.py` audit path is unaffected.
- **Graph per agent (#418)**: for each `agent` build a fresh `AttackKnowledgeGraph`; for each
  `cap in agent.capabilities` call `graph.add_capability(cap.id, cap)`; for every ordered pair
  `(a, b)` of distinct `agent.effective_tools` call `graph.add_tool_chain([a, b], risk_score=0.5)`
  (declared tools may be called in any order); then `ToolChainAnalyzer(graph).analyze()`. Node ids
  are the verbatim tool strings, so the #417 alias map applies inside the analyzer.
- **Lines (#418)**: chain findings and tool findings -> `agent.file`, `agent.line_of("tools")`;
  unrestricted (SA007) -> `agent.file`, `agent.line_of("tools")` (= 1 when the key is absent);
  regex checks over the body -> body line index + `agent.body_line - 1`; over the frontmatter ->
  file lines `1 .. body_line - 2`.
- **Issues (#418)**: every `scan.issues` entry should surface as an audit finding (recommended:
  rule `CC000`, severity `high`, `file`/`line` from the issue, `message` from the issue) so a
  broken agent file cannot silently pass CI.
- **Baseline (#419)**: key agents by `agent.name` (unique per scan). Record `agent.tools`
  (`None` = unrestricted). "Gains a tool" = a name in the new `effective_tools` not in the baseline
  list; "loses its `tools` key" = `unrestricted` flips `False -> True`.
- **Never serialise wholesale**: do not `model_dump()` a scan or agent into a report —
  `system_prompt` and MCP `url`/`args`/`command` (expanded from the environment by
  `load_claude_mcp_config`) may hold secrets. Emit explicit fields: agent `name`, `file`, lines,
  `tools`, `unrestricted`; MCP server `name`, `transport`; hook `event`, `matcher`, `type`.

## Fixtures — `tests/fixtures/claude_code/` (new)

Exact content (fake values only; no `AKIA`/`sk-` lookalikes):

`safe_plugin/.claude-plugin/plugin.json`
```json
{"name": "safe-plugin", "version": "1.0.0", "description": "Read-only review helpers"}
```
`safe_plugin/agents/reviewer.md`
```markdown
---
name: reviewer
description: Reviews code for style issues without changing it.
tools: Read, Grep, Glob
model: sonnet
---
You review code. You never modify files and never contact the network.
```
`safe_plugin/agents/summarizer.md`
```markdown
---
name: summarizer
description: Summarises files the user points at.
tools:
  - Read
  - Grep
---
Summarise the requested files in five bullet points.
```
`safe_plugin/hooks/hooks.json`
```json
{"hooks": {"PostToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "true"}]}]}}
```
`safe_plugin/.mcp.json`
```json
{"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp"]}}}
```

`vulnerable_plugin/.claude-plugin/plugin.json`
```json
{"name": "vulnerable-plugin", "version": "0.1.0"}
```
`vulnerable_plugin/agents/researcher.md` (`tools` on line 4, body on line 7)
```markdown
---
name: researcher
description: Researches topics and posts findings to Slack.
tools: Read, Grep, WebFetch, mcp__slack__send_message
model: sonnet
---
Read the repository, look things up on the web and post a summary to the team channel.
```
`vulnerable_plugin/agents/generalist.md` (no `tools` key)
```markdown
---
name: generalist
description: Does whatever is asked.
model: inherit
---
Do whatever the user asks, using any tool available.
```
`vulnerable_plugin/hooks/hooks.json`
```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/log.sh"}]}]}}
```
`vulnerable_plugin/.mcp.json`
```json
{"mcpServers": {"slack": {"type": "http", "url": "https://mcp.slack.example/mcp"}}}
```

`malformed/agents/broken.md` (invalid YAML on line 3; the fake secret must never appear in an issue)
```markdown
---
name: broken
description: Use when: ziran-fake-secret-0416
tools: Read
---
Broken agent.
```
`malformed/agents/ok.md`
```markdown
---
name: ok
description: A valid sibling.
tools: Read
---
Still parsed.
```
`malformed/agents/README.md` (no frontmatter; must be skipped)
```markdown
# Agents

Notes for humans.
```

Expected parse results (asserted in tests):
- `vulnerable_plugin`: agents `["generalist", "researcher"]` (sorted file order), `plugin.name ==
  "vulnerable-plugin"`, `plugin.version == "0.1.0"`, one hook `(PreToolUse, Bash, command)`, one
  MCP server `slack` with `transport == "streamable-http"`, `issues == []`,
  `files_analyzed == 5`; `researcher.line_of("tools") == 4`, `researcher.body_line == 7`.
- `safe_plugin`: agents `["reviewer", "summarizer"]`, tools `["Read", "Grep", "Glob"]` and
  `["Read", "Grep"]`, no dangerous capability, MCP server `docs` with `transport == "stdio"`,
  `issues == []`, `files_analyzed == 5`.
- `malformed/agents` (and `malformed`): agents `["ok"]`, exactly one issue
  (`file` ends with `broken.md`, `line == 3`, message starts `invalid YAML frontmatter`,
  `"ziran-fake-secret-0416" not in message`), `files_analyzed == 2`.

## Project Structure
```text
ziran/domain/entities/claude_code.py                    # new (models + vocabulary)
ziran/infrastructure/config/claude_code_plugin.py       # new (load_claude_code)
tests/unit/test_claude_code_entities.py                 # new
tests/unit/test_claude_code_plugin_parser.py            # new (unit + integration classes)
tests/fixtures/claude_code/safe_plugin/...              # new (5 files)
tests/fixtures/claude_code/vulnerable_plugin/...        # new (5 files)
tests/fixtures/claude_code/malformed/agents/...         # new (3 files)
```
No existing source file changes. Docs are #423's scope; module docstrings carry the discovery
rules and the "never serialise wholesale" warning.

## Release note for the implementer
Commit as `feat(claude-code): parse plugin manifests and subagent files into capabilities` (plus
`test(claude-code): ...` if split). No `!`, no `BREAKING CHANGE` footer, no `Co-Authored-By`
trailer. PR targets `develop`, body links #416 and restates §Public contract names for #418/#419.

## Phases
- P1: domain models + vocabulary (FR-003, FR-006).
- P2: fixtures (FR-010).
- P3: parser (FR-001, FR-002, FR-004, FR-005, FR-007..FR-009) and issue acceptance.
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.
