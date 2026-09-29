# Tasks: Parse Claude Code plugin manifests and subagent files into capabilities

Branch `037-claude-code-plugin-parser` off `origin/develop` (0.39.0: #417 alias module and #422
`load_claude_mcp_config` are already there). The contract is plan.md §Public contract; #418/#419
are built against it in parallel, so do not rename anything.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM. `@pytest.mark.unit` for entity and `tmp_path`
tests, `@pytest.mark.integration` for tests over the committed fixtures. Fake values only; never
`AKIA`/`sk-` lookalikes.

## Phase 1 — Domain models and tool vocabulary (FR-003, FR-006)

- [ ] T001 [US1][US3][US4] Failing tests in `tests/unit/test_claude_code_entities.py`:
      - `CLAUDE_CODE_BUILTIN_TOOLS` keys are exactly the 12 names in plan.md, in that order, and
        include every key of `tool_aliases._BUILTIN_ALIASES` (guards drift from #417);
      - `claude_code_tool_capability` (parametrized): `Bash` -> (`tool`, dangerous, permission);
        `Read`/`Grep`/`Glob` -> (`data_access`, not dangerous, no permission); `WebFetch` ->
        (`external_api`, dangerous, permission); `Write` -> (`data_access`, dangerous, permission);
        `Agent` -> (`tool`, dangerous, no permission); `Bash(npm test:*)` -> Bash row with
        `id == name == "Bash(npm test:*)"`; `mcp__slack__send_message` -> (`external_api`,
        dangerous, permission); `mcp__docs__search` -> (`external_api`, not dangerous, permission);
        `FooTool` -> (`tool`, not dangerous, no permission); `id == name == tool` in every case;
      - `ClaudeCodeAgent` `tools` normalisation (parametrized): `"Read, Grep, Glob"` ->
        `["Read", "Grep", "Glob"]`; `["Read", " Grep "]` -> `["Read", "Grep"]`;
        `"Read, Bash(git add:*, git commit:*)"` -> 2 entries with the rule intact;
        `"Read, Read, Grep"` -> `["Read", "Grep"]`; `"Read,,Grep,"` -> `["Read", "Grep"]`;
        absent / `None` / `""` / `"  "` / `[]` -> `None`;
        `["Read", 3]` and `{"a": 1}` -> `ValidationError` with `loc[0] == "tools"`;
      - `unrestricted`, `effective_tools` (declared list vs `list(CLAUDE_CODE_BUILTIN_TOOLS)`),
        `capabilities` (ids equal `effective_tools`, same order), `line_of` (known key -> its line,
        unknown key -> `1`);
      - `name` missing or `""` -> `ValidationError` with `loc[0] == "name"`;
      - `ClaudeCodeScan().detected` false when empty; true with a plugin, an agent, or an issue.
- [ ] T002 [US1][US3][US4] Implement `ziran/domain/entities/claude_code.py` exactly per plan.md §A
      (imports: `capability`, `registry.ServerEntry`, `tool_classifier.is_dangerous`; nothing from
      `application` or `infrastructure`). T001 green; `uv run mypy ziran/` clean.

## Phase 2 — Fixtures (FR-010)

- [ ] T003 [P] [US1][US2] Add the 13 fixture files under `tests/fixtures/claude_code/` byte-for-byte
      as listed in plan.md §Fixtures (`safe_plugin/`, `vulnerable_plugin/`, `malformed/agents/`).
      Keep `researcher.md` line layout (`tools` on line 4, body on line 7) and `broken.md` line 3.

## Phase 3 — Parser (FR-001, FR-002, FR-004, FR-005, FR-007, FR-008, FR-009)

- [ ] T004 [US1][US2][US3] Failing tests in `tests/unit/test_claude_code_plugin_parser.py`.
      Integration class (committed fixtures; issue acceptance):
      - `vulnerable_plugin`: every "Expected parse results" bullet in plan.md §Fixtures, plus
        `generalist.unrestricted`, `generalist.effective_tools == list(CLAUDE_CODE_BUILTIN_TOOLS)`,
        `[c.id for c in researcher.capabilities] == researcher.tools`;
      - `safe_plugin`: expected results; `not any(c.dangerous for a in scan.agents for c in
        a.capabilities)`;
      - `malformed/agents` and `malformed`: one issue (`broken.md`, line 3, prefix
        `invalid YAML frontmatter`, fake secret absent), agents `["ok"]`, no exception;
      - `load_claude_code(<vulnerable>/agents/researcher.md)` (single file) -> one agent.
      Unit class (`tmp_path`, write files inline):
      - unclosed fence -> issue line 1; frontmatter `- a` (list) -> issue line 2
        `frontmatter must be a YAML mapping`; `---\n---` -> issue for `name`, line 1;
      - missing `name` -> issue `invalid frontmatter field 'name'`, line 1; `tools: [Read, 3]` on
        line 3 -> issue line 3 naming `tools`; agent not returned in both cases;
      - duplicate `name` in `agents/` and `.claude/agents/` -> first kept, issue at the second
        file's `name` line;
      - `README.md` without fence in `agents/` -> skipped, not counted, no issue;
      - `path` is a `.py` file, a missing path, or a directory with only `app.py` and a
        `.mcp.json` whose JSON is invalid -> `detected is False`, `issues == []`,
        `mcp_servers == []` (MCP not read without a Claude Code root);
      - directory named `agents` passed directly -> its `*.md` parsed; `.claude` passed -> its
        `agents/*.md` parsed; nested `agents/sub/x.md` not parsed (non-recursive);
      - manifest `"agents": "./extra/"` and `"agents": ["./extra/one.md"]` -> followed;
        `"agents": "../outside"` -> issue `escapes the plugin root`, not read;
        `"agents": "./missing"` -> issue `not found`; `"agents": 3` -> issue;
        `"hooks": {...}` inline -> ignored, no issue; a symlinked agent file pointing outside the
        root -> issue, not read;
      - invalid JSON in `plugin.json` on line 2 -> issue `line == 2`, agents still parsed,
        `plugin is None`; `plugin.json` without `name` -> issue naming `name`, `plugin is None`;
      - `hooks.json` with invalid JSON -> issue with line; with `{"hooks": {"Stop": ["x"]}}` ->
        issue `malformed hook entry for event 'Stop'`, other events still parsed; a `prompt`-type
        hook -> `command is None`, `type == "prompt"`;
      - `.mcp.json` `{"mcpServers": {"x": {"type": "ws"}}}` -> one issue whose message is the
        loader's, `mcp_servers == []`;
      - agent file larger than `MAX_FILE_BYTES` -> issue, not parsed;
      - secret hygiene: frontmatter `name: 5\ndescription: ziran-fake-secret-0417` and
        `tools: ziran-fake-secret-0418: x` -> no issue message contains either value;
      - `files_analyzed` counts per plan.md (README and failed reads not counted).
- [ ] T005 [US1][US2][US3] Implement `ziran/infrastructure/config/claude_code_plugin.py` per
      plan.md §B (`load_claude_code`, `MAX_FILE_BYTES`; private helpers for reading, agent files,
      manifest, hooks; `load_claude_mcp_config` reused). Module docstring states the discovery
      rules and the "never serialise a scan wholesale" warning. T004 green.

## Phase 4 — Gates

- [ ] T006 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%, both new modules at 100% line coverage). Existing tests
      (`tests/unit/test_claude_mcp_config.py`, `tests/unit/test_static_analysis.py`,
      `tests/unit/test_cli_main.py`) pass unchanged. Do not commit `uv.lock` drift.
      Commit `feat(claude-code): parse plugin manifests and subagent files into capabilities`
      (no `!`, no `BREAKING CHANGE`, no `Co-Authored-By`); PR to `develop` referencing #416 and
      restating the contract names for #418/#419.
