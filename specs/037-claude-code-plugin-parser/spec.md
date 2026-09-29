# Feature Specification: Parse Claude Code plugin manifests and subagent files into capabilities

**Feature Branch**: `037-claude-code-plugin-parser`
**Created**: 2026-09-29
**Status**: Active
**Issue**: #416 (part of epic #415). **Builds on**: #417 / spec `033-claude-code-chain-patterns`
(`ziran/application/knowledge_graph/tool_aliases.py`), #422 / spec `035-watch-registry-claude-config`
(`ziran/infrastructure/config/claude_mcp_config.py`). **Consumers (implemented in parallel against
the contract in [plan.md](plan.md#public-contract))**: #418 (`ziran audit` over plugins), #419
(allowlist baseline), #420 (GitHub Action). **Downstream**: WUWEI #36 (audit of its `agents/`
directory with a committed baseline).
**Input**: ZIRAN has no reader for Claude Code agent definitions. `ziran audit` globs only `*.py`,
and `ToolChainAnalyzer` needs a graph built from a live agent. Claude Code declares an agent's tools
statically: `agents/*.md` (plugin) and `.claude/agents/*.md` (project) carry YAML frontmatter
(`name`, `description`, `tools`, `model`) and a markdown body (the system prompt); a plugin adds
`.claude-plugin/plugin.json`, `hooks/hooks.json` and `.mcp.json`. This feature reads those files
into typed models, one capability set per agent, without executing anything and without network.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — One capability set per declared agent (Priority: P1)
The `ziran audit` command (#418) points the parser at a plugin directory and gets back, for every
agent file, the agent's name, its declared tools verbatim and one `AgentCapability` per tool, so it
can build a knowledge graph and run `ToolChainAnalyzer` over the declared tools.

**Why this priority**: This is the issue's first acceptance criterion and the input #418, #419 and
#420 are blocked on.

**Independent Test**: `load_claude_code(tests/fixtures/claude_code/vulnerable_plugin)` in a unit
test; assert the returned agents and their capabilities.

**Acceptance Scenarios**:
1. **Given** the vulnerable fixture plugin with two agents — `researcher` declaring
   `tools: Read, Grep, WebFetch, mcp__slack__send_message` and `generalist` with no `tools` key —
   **When** parsed, **Then** `scan.agents` has exactly two entries (sorted by file path);
   `researcher.tools == ["Read", "Grep", "WebFetch", "mcp__slack__send_message"]`,
   `researcher.unrestricted is False` and `[c.id for c in researcher.capabilities]` equals that
   list; `generalist.tools is None`, `generalist.unrestricted is True` and
   `generalist.effective_tools == list(CLAUDE_CODE_BUILTIN_TOOLS)`.
2. **Given** the safe fixture plugin (two agents, `Read, Grep, Glob` as a comma string and
   `[Read, Grep]` as a YAML list), **When** parsed, **Then** both agents are restricted, `tools`
   hold exactly the declared names and no capability is `dangerous`.
3. **Given** either fixture, **When** parsed, **Then** `scan.plugin.name` is the manifest name,
   `scan.plugin.version` the manifest version, `scan.hooks` lists each hook
   (event, matcher, type, command) from `hooks/hooks.json`, `scan.mcp_servers` lists each server
   (name, transport) from `.mcp.json`, and `scan.issues == []`.

### User Story 2 — Malformed files are reported, not fatal (Priority: P1)
An audit over a directory that contains one broken agent file still audits every other agent and
tells the operator which file and line is broken.

**Why this priority**: Issue acceptance criterion; a parser crash would turn a CI audit into
"could not run" for every plugin with one typo.

**Independent Test**: `load_claude_code(tests/fixtures/claude_code/malformed/agents)`; assert the
issue list and that the valid agent is still returned.

**Acceptance Scenarios**:
1. **Given** `broken.md` whose frontmatter line 3 is `description: Use when: the user asks`
   (invalid YAML), **When** parsed, **Then** no exception is raised, `scan.issues` contains one
   entry with `file` ending in `broken.md`, `line == 3` and a message starting
   `invalid YAML frontmatter`, and the valid sibling agent `ok.md` is in `scan.agents`.
2. **Given** an agent file whose frontmatter opens with `---` but never closes, **Then** one issue
   with `line == 1`.
3. **Given** frontmatter without `name`, or with `tools: [Read, 3]`, **Then** one issue whose
   `line` is the line of the offending key (`1` when the key is absent), naming the field, and the
   agent is not returned.
4. **Given** invalid JSON in `hooks/hooks.json` or `plugin.json`, **Then** one issue with the JSON
   error line; the rest of the plugin is still parsed.
5. **Given** any issue, **Then** its `message` contains no value taken from the file (key names and
   error kinds only), so a secret in a broken file cannot leak through the issue list.

### User Story 3 — Unrestricted agents are explicit (Priority: P1)
A reviewer (and #418's SA007, #419's "lost its `tools` key" rule) can tell an agent that inherits
every tool from one that declares a list.

**Acceptance Scenarios**:
1. **Given** an agent with no `tools` key, with `tools:` (YAML null), `tools: ""` or `tools: []`,
   **Then** `tools is None`, `unrestricted is True`, and `capabilities` covers every entry of
   `CLAUDE_CODE_BUILTIN_TOOLS` (including `Bash`, `Read`, `WebFetch`, `Write`, `Agent`).
2. **Given** `tools: Read, Grep` **Then** `unrestricted is False`.

### User Story 4 — Tool vocabulary mapped to capability metadata (Priority: P2)
Every declared tool becomes an `AgentCapability` whose `id` and `name` are the tool string verbatim
(so `ToolChainAnalyzer` resolves it through `canonical_tool_name`) and whose `type`, `dangerous`
and `requires_permission` follow Claude Code semantics.

**Acceptance Scenarios**:
1. **Given** `Bash`, **Then** type `tool`, `dangerous`, `requires_permission`. **Given** `Read`,
   `Grep`, `Glob`, **Then** type `data_access`, not dangerous, no permission. **Given** `WebFetch`,
   **Then** type `external_api`, dangerous, permission. (Full table: plan.md, FR-006.)
2. **Given** `Bash(npm test:*)`, **Then** the capability id is `Bash(npm test:*)` verbatim and its
   metadata is that of `Bash`.
3. **Given** `mcp__slack__send_message`, **Then** type `external_api`, `requires_permission`, and
   `dangerous` equal to the existing domain classifier `is_dangerous(tool)` (`True` here).
4. **Given** an unknown name `FooTool`, **Then** type `tool`, `requires_permission` false,
   `dangerous == is_dangerous("FooTool")`.

### Edge Cases
- `tools` as a comma string with permission rules containing commas
  (`Read, Bash(git add:*, git commit:*)`) splits only on commas outside parentheses.
- Duplicate entries in `tools` are removed, first occurrence kept, order preserved.
- A `.md` file in an agents directory whose first line is not `---` (e.g. `README.md`) is not an
  agent file: skipped silently, not counted, no issue (Claude Code does not load it either).
- Two agent files declaring the same `name` in one scan: the first (by discovery order) is kept, the
  second is reported as an issue at its `name` line and not returned, so agent names are unique keys
  for #419's baseline.
- A path in `plugin.json` (`agents`, `hooks`, `mcpServers`) that resolves outside the plugin root,
  or does not exist, is an issue; the path is not read. Every file the parser reads must resolve
  inside the scanned root (symlinks included).
- A file over 1 MiB is an issue and is not parsed.
- Inline `hooks` / `mcpServers` objects in `plugin.json` are not read in this version (debug log,
  no issue); only path strings are followed.
- `PATH` is a single `.md` file: parsed as one agent file. `PATH` is any other file, or does not
  exist: empty scan, `detected is False`.
- A directory with no plugin manifest and no agent file (e.g. a pure Python project, even one with a
  `.mcp.json`): empty scan, `detected is False`, `.mcp.json` and hooks are not read — Python-agent
  audits are unaffected.
- `PATH` whose basename is `agents` (WUWEI #36 runs on `agents/`) is itself an agent directory.
- Unknown frontmatter keys (`color`, `permissionMode`, ...) are ignored but their lines are kept in
  `key_lines`.
- MCP config values: `.mcp.json` is loaded by the existing `load_claude_mcp_config`, which expands
  `${VAR}` from the environment; consumers must emit only `name` and `transport` of an MCP server
  (never `url`, `args`, `command`, `env`, `headers`).

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (entry point)**: `ziran.infrastructure.config.claude_code_plugin.load_claude_code(path:
  Path) -> ClaudeCodeScan` MUST discover and parse the Claude Code files under `path` per the
  discovery rules in plan.md §Public contract, and MUST NOT raise for any file content, missing
  file, unreadable file or permission problem (all become `ClaudeCodeParseIssue`s).
- **FR-002 (agent files)**: Each agent file (`agents/*.md`, `.claude/agents/*.md`, `PATH/*.md` when
  `PATH` is named `agents`, and `plugin.json` `agents` paths) MUST yield one `ClaudeCodeAgent` with
  `name`, `description`, `tools`, `model` from the frontmatter, `system_prompt` = body after the
  closing `---`, `file` = the path string, `key_lines` = 1-based line of every top-level
  frontmatter key, and `body_line` = 1-based line of the first body line.
- **FR-003 (tools semantics)**: `tools` MUST be the declared names verbatim (comma string or YAML
  list; stripped; empty entries dropped; de-duplicated preserving order); absent, null, empty string
  or empty list MUST be `None` (unrestricted). `effective_tools` MUST be the declared list, or every
  `CLAUDE_CODE_BUILTIN_TOOLS` name when unrestricted. `capabilities` MUST be one
  `AgentCapability` per `effective_tools` entry, same order.
- **FR-004 (plugin manifest)**: `.claude-plugin/plugin.json` MUST yield `ClaudeCodePlugin(name,
  version, description, file)`; its `agents`, `hooks`, `mcpServers` path strings (string or list of
  strings, relative to the plugin root) MUST be followed in addition to the default locations.
- **FR-005 (hooks and MCP)**: `hooks/hooks.json` (and manifest `hooks` paths) MUST yield one
  `ClaudeCodeHook(event, matcher, type, command, file)` per hook entry. `.mcp.json` (and manifest
  `mcpServers` paths) MUST be loaded with the existing `load_claude_mcp_config` (reused, not
  copied) into `scan.mcp_servers`; its `ClaudeConfigError`/`OSError` become issues with the
  loader's (value-free) message.
- **FR-006 (tool vocabulary)**: The domain MUST provide `CLAUDE_CODE_BUILTIN_TOOLS` and
  `claude_code_tool_capability(tool: str) -> AgentCapability` implementing the table in plan.md
  (built-ins by table on the name before any `(`; `mcp__*` as `external_api`, permission-gated,
  dangerous per `ziran.domain.tool_classifier.is_dangerous`; anything else `tool`, dangerous per
  `is_dangerous`). `id == name == tool` verbatim.
- **FR-007 (issues)**: Every problem MUST be reported as `ClaudeCodeParseIssue(file, line, message)`
  with `line` 1-based when known (YAML error mark, offending frontmatter key, JSON error line) and
  `None` otherwise; the offending agent/manifest/hook entry is skipped; parsing continues with the
  next file. Messages MUST NOT contain values read from the file (use `exc.problem`, never
  `str(yaml_error)`; pydantic `errors(include_input=False)`; JSON `lineno` only).
- **FR-008 (trust boundary)**: The parser MUST NOT read a file that resolves outside the scanned
  root or exceeds 1 MiB; it MUST use `yaml.safe_load` / `yaml.compose(..., Loader=SafeLoader)`
  only; it MUST NOT execute hooks, start MCP servers or touch the network.
- **FR-009 (detection)**: `ClaudeCodeScan.detected` MUST be true iff a plugin manifest was found,
  or at least one agent file (a `.md` starting with `---`) was found. Hooks and MCP files MUST be
  read only when `detected` holds.
- **FR-010 (fixtures)**: `tests/fixtures/claude_code/safe_plugin/`,
  `tests/fixtures/claude_code/vulnerable_plugin/` and `tests/fixtures/claude_code/malformed/agents/`
  MUST exist with the content listed in plan.md §Fixtures; #418 and #419 reuse them.
- **FR-011**: No new runtime dependency (PyYAML and Pydantic are existing). No network or LLM in
  tests. Hexagonal layering: models and vocabulary in `ziran/domain/entities/claude_code.py`
  (imports domain only); parser in `ziran/infrastructure/config/claude_code_plugin.py` (imports
  domain and `infrastructure/config/claude_mcp_config.py` only, never `ziran.application`).

### Key Entities
- **ClaudeCodeAgent**: one subagent definition; identity `name`; declared `tools` or `None`.
- **ClaudeCodePlugin**: the plugin manifest (name, version, description).
- **ClaudeCodeHook**: one hook entry, metadata only.
- **ClaudeCodeParseIssue**: file + line + value-free message.
- **ClaudeCodeScan**: result of one `load_claude_code` call (plugin, agents, hooks, MCP servers,
  issues, files analysed).

### Assumptions (conservative readings, recorded instead of a clarify round)
- **Module path**: the issue says "e.g. `ziran/infrastructure/claude_code/`". The parser is one
  module, so it goes next to the existing Claude Code MCP loader in `ziran/infrastructure/config/`
  (no new package). Models go in `ziran/domain/entities/` so application-layer consumers (#418
  chain analysis, #419 baseline) can import them without depending on infrastructure.
- **Empty `tools`**: Claude Code documents only "omitted = inherits all tools". Behaviour for
  `tools:` (null), `""` and `[]` is undocumented, so they are treated as omitted (unrestricted).
  This over-reports rather than under-reports.
- **Built-in vocabulary**: `Agent, Bash, Edit, Glob, Grep, NotebookEdit, Read, Skill, TodoWrite,
  WebFetch, WebSearch, Write` — the current Claude Code built-ins that matter for access control
  (every #417 alias key is included). The unrestricted set is this list; MCP tools of an
  unrestricted agent cannot be enumerated statically and are not added.
  `requires_permission` follows the Claude Code tools table (permission required for Bash, Edit,
  NotebookEdit, Skill, WebFetch, WebSearch, Write and every MCP tool).
- **`dangerous`** is capability metadata (graph node attribute), not a finding. `Read`/`Grep`/`Glob`
  are not dangerous on their own (Claude Code does not gate them); exfiltration is the chain
  analyzer's job (#417 patterns). The #417 alias map lives in the application layer, so the
  infrastructure/domain code does not import it; MCP danger uses the existing domain classifier.
- **Strict YAML**: frontmatter is parsed with `yaml.safe_load`. Real-world descriptions with an
  unquoted `: ` are reported as malformed even if Claude Code tolerates them; the fix is quoting.
  No lenient fallback parser (ceiling recorded; revisit if it fires on popular plugins).
- **Missing frontmatter fence** (`README.md` in `agents/`): not an agent, skipped silently.
  **Missing `name`**: issue, agent skipped. **Missing `description`**: accepted as `""`.
- **Discovery is non-recursive** (`agents/*.md`, exactly as the issue states); user-level
  `~/.claude/agents` is parsed only when passed as `PATH` (never read implicitly — CI must not
  depend on the runner's home directory). Hooks in `.claude/settings.json` and `disallowedTools`
  are out of scope for this issue.
- **Issues do not fail anything by themselves**: the parser only reports. #418 decides how issues
  surface in `ziran audit` (plan.md recommends a finding per issue).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: Vulnerable fixture: two agents, declared tools verbatim, `generalist.unrestricted`.
- **SC-002**: Malformed fixture: issue with `file`/`line == 3`, no exception, valid sibling parsed.
- **SC-003**: Safe fixture: two restricted agents, no dangerous capability, no issues.
- **SC-004**: No issue message in the test suite contains the fake secret planted in a broken file.
- **SC-005**: Existing tests (notably `tests/unit/test_claude_mcp_config.py`,
  `tests/unit/test_static_analysis.py`, `tests/unit/test_cli_main.py`) pass unchanged.
- **SC-006**: All gates pass — ruff, ruff format, mypy (strict), pytest coverage >= 85%, and the
  new modules are fully covered by the new tests.
