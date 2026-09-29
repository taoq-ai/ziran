# Feature Specification: `ziran audit` over Claude Code plugins with static checks and declared-tool chains

**Feature Branch**: `038-audit-claude-code-plugins`
**Created**: 2026-09-29
**Status**: Active
**Issue**: #418 (part of epic #415). **Depends on**: #416 / spec `037-claude-code-plugin-parser`
(`load_claude_code`, `ClaudeCodeScan`, `ClaudeCodeAgent`, fixtures under
`tests/fixtures/claude_code/`), #417 / spec `033-claude-code-chain-patterns` (released in 0.39.0:
`canonical_tool_name`, `unrestricted_execution`, `claude_code` chain patterns), spec
`036-audit-json-output` (released: `ziran audit --format text|json`, exit codes 0/1/2).
**Consumers (implemented in parallel against [plan.md §Public contract](plan.md#public-contract))**:
#419 (allowlist baseline on top of this audit output), #420 (GitHub Action, SARIF), #423 (guide).
**Downstream**: WUWEI #36 runs the ZIRAN action in audit mode over its `agents/` directory; a
widened agent must fail the build naming the chain it creates. WUWEI pins the release and writes an
adapter against the JSON below, so every flag, JSON field and exit code here is a stable contract.
**Input**: `ziran audit PATH` globs only `*.py`. A Claude Code plugin declares each subagent's
tools in `agents/*.md` frontmatter and its system prompt in the markdown body; nothing audits
those files today, and `ToolChainAnalyzer` only runs on graphs built from a live or in-process
agent. #416 parses the files into `ClaudeCodeAgent` models; this feature wires them into
`ziran audit`: per agent, the static checks SA001/SA003/SA004/SA007 and tool-chain analysis over
the declared tool set, with no execution, no LLM and no network.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A vulnerable plugin fails the audit (Priority: P1)
A plugin author runs `ziran audit ./my-plugin/`. An agent that declares `Read` and `WebFetch`, or
that has no `tools` key at all, is reported with the agent file and line, the chain's tools, and a
non-zero exit.

**Why this priority**: The issue's first acceptance criterion and the reason WUWEI #36 is blocked.

**Independent Test**: `CliRunner` over `tests/fixtures/claude_code/vulnerable_plugin` (from #416),
in text and JSON mode; assert exit code and the JSON findings.

**Acceptance Scenarios**:
1. **Given** the vulnerable fixture plugin (`researcher` declares
   `Read, Grep, WebFetch, mcp__slack__send_message` with `tools` on line 4; `generalist` has no
   `tools` key), **When** `ziran audit PATH --format json` runs, **Then** the exit code is `1` and
   `findings` contains a row `{"rule": "CC001", "severity": "critical", "agent": "researcher",
   "tools": ["Read", "WebFetch"], "line": 4}` whose `file` ends with `agents/researcher.md` and whose
   `message` names `data_exfiltration` and `Read -> WebFetch`.
2. **Given** the same plugin, **When** audited, **Then** `findings` contains a row
   `{"rule": "SA007", "severity": "high", "agent": "generalist", "line": 1}` whose `file` ends with
   `agents/generalist.md`.
3. **Given** the same plugin, **When** audited, **Then** `generalist` also has CC001 rows for its
   inherited built-in set, including `{"tools": ["Bash"], "severity": "high"}`
   (`unrestricted_execution`) and a critical `["Read", "WebFetch"]` chain.
4. **Given** the same plugin, **When** `ziran audit PATH` runs in text mode (no flags), **Then** the
   exit code is `1` (critical findings exist) and the table lists CC001 and SA007 rows with
   `file:line` locations.
5. **Given** the same plugin, **When** audited in JSON mode, **Then** `files_analyzed == 5` (five
   plugin files parsed by #416 plus zero `*.py` files).

### User Story 2 — A least-privilege plugin passes (Priority: P1)
**Acceptance Scenarios**:
1. **Given** the safe fixture plugin (`reviewer`: `Read, Grep, Glob`; `summarizer`: `[Read, Grep]`),
   **When** `ziran audit PATH` runs in text mode, JSON mode, and JSON mode with `--severity low`,
   **Then** every run exits `0` and the JSON `findings` is `[]`, `files_analyzed == 5`.

### User Story 3 — Python-agent scanning is unchanged (Priority: P1)
**Acceptance Scenarios**:
1. **Given** any path without Claude Code definitions (`scan.detected is False`), **When** audited
   in any mode, **Then** output, JSON keys and exit codes are exactly as on `develop`: every
   existing test in `tests/unit/test_cli_main.py::TestAuditCommand` and
   `tests/unit/test_static_analysis.py` passes unmodified, and JSON finding rows keep exactly the
   keys `{rule, severity, file, line, message}`.
2. **Given** a directory that holds both `*.py` files and Claude Code agents (for example a repo
   with `.claude/agents/`), **When** audited, **Then** the Python findings are still reported
   (unchanged) and the Claude Code findings are appended after them.

### User Story 4 — Secrets and broken files (Priority: P1)
**Acceptance Scenarios**:
1. **Given** an agent whose body line 2 (file line `body_line + 1`) is
   `api_key = "ziran-fake-secret-0418"`, **When** audited in JSON mode, **Then** there is an SA001
   `critical` row for that agent at that file line and the literal `ziran-fake-secret-0418` appears
   nowhere in stdout.
2. **Given** `tests/fixtures/claude_code/malformed`, **When**
   `ziran audit PATH --format json --severity high` runs, **Then** the exit code is `1`, one row has
   `rule == "CC000"`, `severity == "high"`, `line == 3`, `file` ending with `broken.md`,
   `agent == null`, `tools == []`, the valid sibling `ok` produces no finding, and
   `ziran-fake-secret-0416` appears nowhere in stdout.

### User Story 5 — WUWEI #36 gate (Priority: P2)
WUWEI runs `ziran audit agents/ --format json` (the directory itself is named `agents`, #416
discovery rule 3). Adding `WebFetch` to an agent that already declares `Read` yields a new critical
`CC001` row naming the agent and `Read -> WebFetch`, and exit `1`. The baseline comparison that
turns "new chain" into the pass/fail decision is #419; this story only requires that the row
exists with `agent`, `file`, `line`, `tools` and a message naming the chain.

### Edge Cases
- `PATH` does not exist: Click usage error, exit `2` (unchanged).
- `PATH` is a single agent `.md` file (first line `---`): only the Claude Code checks run; the
  Python regex checks are not applied to markdown (they would flag `tools: Bash` as SA003 and
  duplicate SA001). A `.md` file without frontmatter keeps today's behaviour (`analyze_file`).
- `PATH` is a directory named `agents` or contains `agents/` / `.claude/agents/` with `.md` files
  that start with `---` but are not agents (for example docs with frontmatter): they surface as
  `CC000` findings (missing `name`). Accepted: #416's discovery is limited to those three places.
- Agent with a single declared tool: no pair to chain; only single-tool findings apply
  (`["Bash"]` gives the `unrestricted_execution` CC001 row).
- Agent declaring 12+ tools, or unrestricted: chain analysis stays fast because cycle enumeration
  is disabled for declared-tool graphs (FR-006); measured on `develop`: 12 built-ins, 29 chains,
  about 0.02 s. With cycles enabled, 8 tools already produce 19,969 cycle findings and 12 tools do
  not terminate in practice.
- Scoped entries (`Bash(npm test:*)`) keep the Bash capability row (#416), so SA003 still fires;
  `canonical_tool_name` handles `Read(./.env)` / `Bash(git push:*)` for chain matching (#417).
- Unrestricted agents also inherit MCP tools at runtime; their names are unknown statically, so
  they are not added to `effective_tools` (#416 ceiling). Declared `mcp__*` tools are analysed.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (detection)**: `ziran audit PATH` MUST call `load_claude_code(Path(PATH))` (#416). When
  `scan.detected` is `False`, the command MUST behave exactly as on `develop` (US3).
- **FR-002 (composition)**: When `scan.detected` is `True`:
  - `PATH` is a directory: the existing `StaticAnalyzer.analyze_directory` report is produced as
    today, then the Claude Code findings are appended and `scan.files_analyzed` is added to
    `files_analyzed`.
  - `PATH` is a file: only the Claude Code findings are produced (`files_analyzed ==
    scan.files_analyzed`); `analyze_file` is not run on the markdown.
- **FR-003 (per-agent static checks)** — for every `agent` in `scan.agents`, in scan order:
  - **SA001** (`critical`): the existing `secret_checks` from the active `StaticAnalysisConfig`
    run over the system prompt (each body line at file line `body_line + index`), the
    `description` value (at `line_of("description")`) and the declared `tools` joined by `", "`
    (at `line_of("tools")`). Message = the check's existing message. The matched text is never
    emitted.
  - **SA003** (`high`): one finding per declared tool (not for unrestricted agents; SA007 covers
    those) whose `claude_code_tool_capability(tool).dangerous` is `True`, at `line_of("tools")`,
    `tools == [tool]`.
  - **SA004** (`medium`): one finding per declared wildcard grant, at `line_of("tools")`,
    `tools == [tool]`. A wildcard grant is an entry ending in `(*)`, an `mcp__` entry with no tool
    segment (`mcp__<server>`), or an `mcp__` entry containing `*`.
  - **SA007** (`high`): one finding when `agent.unrestricted`, at `line_of("tools")` (`1`, the
    opening fence, because the key is absent), `tools == []`.
- **FR-004 (declared-tool chains, CC001)**: for every agent, a fresh `AttackKnowledgeGraph` with
  one capability node per `agent.capabilities` entry (`graph.add_capability(cap.id, cap)`) and a
  `CAN_CHAIN_TO` edge for every ordered pair of distinct `agent.effective_tools`
  (`graph.add_tool_chain([a, b], risk_score=0.5)`); then
  `ToolChainAnalyzer(graph).analyze(include_cycles=False)`. Each returned `DangerousChain` becomes
  one CC001 finding: `severity = chain.risk_level`, `tools = chain.tools`, file `agent.file`, line
  `agent.line_of("tools")`. No execution, no LLM, no network.
- **FR-005 (parse issues, CC000)**: every `scan.issues` entry becomes one CC000 finding (`high`,
  `file`/`line`/`message` from the issue, no agent, no tools), listed before the agent findings.
- **FR-006 (analyzer option)**: `ToolChainAnalyzer.analyze` MUST gain a keyword-only
  `include_cycles: bool = True`; `False` skips `_find_chain_cycles`. The default keeps every
  existing caller and test byte-for-byte unchanged.
- **FR-007 (finding identity)**: `StaticFinding` MUST gain two defaulted fields, `agent: str | None
  = None` and `tools: tuple[str, ...] = ()`. Every Claude Code finding except CC000 carries
  `agent = agent.name`. CC001 findings are unique per `(agent, tuple(tools))`.
- **FR-008 (JSON)**: With `--format json` and `scan.detected`, every finding row (Python rows
  included) MUST carry the keys `rule, severity, file, line, message, agent, tools` (`agent` string
  or `null`, `tools` list of strings, `[]` when none). When `scan.detected` is `False`, rows keep
  exactly the five 036 keys. The top-level object stays `{"files_analyzed", "findings"}`. No
  system prompt, description, hook command or MCP `url`/`args`/`command`/`env` value is ever
  emitted (no `model_dump()` of a scan or agent).
- **FR-009 (filters and exit codes)**: `--severity` filtering and exit codes apply to the merged
  report exactly as in spec 036: text mode exits `1` iff a `critical` finding remains; JSON mode
  exits `1` iff any finding remains with `--severity`, else iff a `critical` finding exists; `2`
  for usage errors. No new exit code, no new CLI flag.
- **FR-010 (text output)**: Text mode reuses `_display_audit_report` unchanged; the agent name and
  chain are in `message`, the location is `file:line`.
- **FR-011 (docs)**: `docs/reference/cli.md` `ziran audit` section MUST document Claude Code
  detection, the rule table (CC000, CC001, SA001, SA003, SA004, SA007 for agents), the two extra
  JSON keys and when they appear, and that exit codes are unchanged. The `ziran audit` docstring
  gains a plugin example.
- **FR-012 (layering)**: The audit logic lives in the application layer and imports only domain and
  application modules; only the CLI imports `ziran.infrastructure.config.claude_code_plugin`.

### Assumptions (recorded, most conservative reading)
- "The JSON, Markdown and SARIF outputs apply unchanged": `ziran audit` has only `text` and `json`
  today (SARIF exists for `ziran ci`, Markdown for `ziran report`). This feature adds no format;
  it keeps the existing ones working. SARIF for `audit` is #420's scope.
- "SA001 … over the markdown body and frontmatter": SA001 runs over the system prompt plus the
  frontmatter values that #416 retains (`description`, `tools`); other frontmatter keys are not
  retained by the parser and are not scanned (ceiling). SA003/SA004/SA007 are defined over the
  declared `tools` frontmatter key, because regex SA003 over prose (for example "terminal") would be
  noise and misses `WebFetch`.
- SA004 had no implementation before; for agents it is the wildcard-grant rule in FR-003.
- CC000 uses `high` (the #416 recommendation): a broken agent file fails `--severity high` gates
  (WUWEI) but not the default text run, consistent with the existing critical-only default.
- Tool strings are emitted verbatim in `tools` and in messages. They are declarations, not secret
  fields; a secret embedded in a permission rule is still flagged by SA001 (FR-003).
- The Python path keeps running on directories that contain agents (US3.2); a plugin's `*.py` hook
  scripts are therefore also audited.

### Key Entities
- **Claude Code audit report**: the existing `AnalysisReport` (`files_analyzed`, `findings`), with
  `StaticFinding` extended by `agent` and `tools`. No new model.
- **Rule ids**: CC000 (parse issue), CC001 (declared-tool chain, including single-tool
  `unrestricted_execution`), SA001, SA003, SA004, SA007 (agent forms).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1 and US2 acceptance scenarios pass through `CliRunner` over the #416 fixtures.
- **SC-002**: Every pre-existing test passes unmodified (US3), including
  `tests/unit/test_chain_analyzer.py` with the default `include_cycles=True`.
- **SC-003**: No secret literal from a fixture or `tmp_path` agent appears in any stdout captured by
  the tests (US4).
- **SC-004**: Auditing an unrestricted agent completes in well under one second (no cycle
  enumeration).
- **SC-005**: All gates pass: ruff, ruff format, mypy strict, pytest coverage >= 85%; no new
  runtime dependency; no network or LLM in tests.
