# Tasks: `ziran audit` over Claude Code plugins with static checks and declared-tool chains

Prerequisite: #416 (`037-claude-code-plugin-parser`) merged into `develop`; rebase this branch on
it before T004 (it provides `load_claude_code`, `ClaudeCodeAgent`, `ClaudeCodeScan`,
`claude_code_tool_capability` and `tests/fixtures/claude_code/`). Do not modify #416's files or
fixtures.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM. New unit tests carry `@pytest.mark.unit`;
tests added to `tests/unit/test_cli_main.py` follow that file (no markers). Fake values only
(`ziran-fake-secret-0418`); never `AKIA`/`sk-` lookalikes. Names, messages and JSON keys are
exactly those in [plan.md §Public contract](plan.md#public-contract).

## Phase 1 — Foundations (FR-006, FR-007)

- [ ] T001 [P] Failing test in `tests/unit/test_chain_analyzer.py`: build an
      `AttackKnowledgeGraph` with one `add_capability` node per tool of
      `["Agent", "Bash", "Edit", "Glob", "Grep", "NotebookEdit", "Read", "Skill", "TodoWrite",
      "WebFetch", "WebSearch", "Write"]` and `add_tool_chain([a, b], 0.5)` for every ordered pair;
      `ToolChainAnalyzer(graph).analyze(include_cycles=False)` returns no chain with
      `chain_type == "cycle"`, contains `tools == ["Read", "WebFetch"]` with `risk_level ==
      "critical"` and `tools == ["Bash"]` with `vulnerability_type == "unrestricted_execution"`.
      Second test: on a 4-tool complete graph (`Read, Grep, WebFetch, mcp__slack__send_message`)
      `analyze()` (default) still returns `cycle` chains (default unchanged). Confirm the first
      fails (`TypeError: unexpected keyword argument`).
- [ ] T002 Implement `ToolChainAnalyzer.analyze(self, *, include_cycles: bool = True)` in
      `ziran/application/knowledge_graph/chain_analyzer.py`: guard the
      `_find_chain_cycles` call with `if include_cycles:`; update the docstring step list. T001
      passes; the rest of `test_chain_analyzer.py` passes unmodified.
- [ ] T003 [P] Failing test in `tests/unit/test_claude_code_audit.py` (new file):
      `StaticFinding(check_id="X", message="m", severity="low", file_path="f")` has
      `agent is None` and `tools == ()`; `StaticFinding(..., agent="a", tools=("Read",))` keeps them.
      Then add the two defaulted fields `agent: str | None = None`,
      `tools: tuple[str, ...] = ()` at the end of `StaticFinding` in
      `ziran/application/static_analysis/analyzer.py`. `tests/unit/test_static_analysis.py` passes
      unmodified.

## Phase 2 — Audit module (FR-003, FR-004, FR-005, US1, US2, US4)

All in `tests/unit/test_claude_code_audit.py` against in-memory models
(`ClaudeCodeAgent(name=..., tools=..., file="agents/x.md", key_lines={"name": 2, "tools": 4,
"description": 3}, system_prompt=..., body_line=7)`, `ClaudeCodeScan(root=".", ...)`).

- [ ] T004 Failing tests for `agent_chains(agent)`:
      - tools `"Read, Grep, WebFetch, mcp__slack__send_message"` -> exactly the four direct critical
        `data_exfiltration` chains (`[Read, WebFetch]`, `[Read, mcp__slack__send_message]`,
        `[Grep, WebFetch]`, `[Grep, mcp__slack__send_message]`), none of `chain_type "cycle"`;
      - tools `"Read, Grep, Glob"` -> `[]`; tools `"Read"` -> `[]`;
      - tools `"Bash"` -> one `unrestricted_execution` chain `["Bash"]`, `risk_level == "high"`;
      - unrestricted agent (no `tools`) -> contains `["Read", "WebFetch"]` critical and `["Bash"]`,
        completes in under 1 s.
- [ ] T005 Failing tests for `audit_claude_code(scan)` rule by rule:
      - SA007: unrestricted agent without `tools` key -> one `SA007`, `high`, `line_number == 1`,
        `agent == name`, `tools == ()`, exact message; no SA003 for that agent.
      - SA003: declared `"Read, WebFetch, mcp__slack__send_message"` -> two `SA003` `high` at the
        `tools` line with `tools == ("WebFetch",)` and `("mcp__slack__send_message",)`, exact
        messages; `"Read, Grep, Glob"` -> none.
      - SA004: declared `"Bash(*), mcp__github, mcp__slack__*, Bash(npm test:*)"` -> three `SA004`
        `medium` (`Bash(*)`, `mcp__github`, `mcp__slack__*`), none for `Bash(npm test:*)`.
      - SA001: body line 2 `api_key = "ziran-fake-secret-0418"` with `body_line=7` -> one `SA001`
        `critical`, `line_number == 8`, `agent` set; a secret-shaped `description` is reported at
        `key_lines["description"]`; the literal is absent from every `message`.
      - CC001: rows mirror `agent_chains`: `severity == chain.risk_level`,
        `tools == tuple(chain.tools)`, `line_number == line_of("tools")`, message
        `"Agent 'researcher': data_exfiltration via Read -> WebFetch"`; `(agent, tools)` unique.
      - CC000: `scan.issues=[ClaudeCodeParseIssue(file="agents/b.md", line=3, message="m")]` ->
        first finding `CC000`, `high`, `file_path == "agents/b.md"`, `line_number == 3`,
        `agent is None`.
      - Ordering: CC000 first, then per agent SA001, SA003, SA004, SA007, CC001;
        `report.files_analyzed == scan.files_analyzed`.
      - A custom `StaticAnalysisConfig` passed as `config` is used for SA001 (a config with an extra
        secret pattern flags a line the default does not).
- [ ] T006 Implement `ziran/application/static_analysis/claude_code_audit.py` with
      `agent_chains` and `audit_claude_code` per plan §3 (virtual-file SA001 via `_run_check` +
      `dataclasses.replace`, fixed recommendations, `itertools.permutations` for edges,
      `analyze(include_cycles=False)`). Module docstring states the rule table and the
      "never serialise a scan wholesale" rule. T004-T005 pass; mypy strict clean.

## Phase 3 — CLI wiring and acceptance (FR-001, FR-002, FR-008..FR-010, US1-US5)

In `tests/unit/test_cli_main.py::TestAuditCommand`; fixture root
`Path(__file__).parents[1] / "fixtures" / "claude_code"`; parse `result.stdout`.

- [ ] T007 Failing CLI tests:
      - `test_audit_claude_code_vulnerable_json`: `audit vulnerable_plugin --format json` -> exit 1;
        `files_analyzed == 5`; every row has keys exactly
        `{rule, severity, file, line, message, agent, tools}`; a row
        `rule == "CC001"`, `severity == "critical"`, `agent == "researcher"`,
        `tools == ["Read", "WebFetch"]`, `line == 4`, `file` ends with `researcher.md`, message
        contains `data_exfiltration` and `Read -> WebFetch`; a row `rule == "SA007"`,
        `agent == "generalist"`, `line == 1`, `severity == "high"`; a generalist CC001 row with
        `tools == ["Bash"]`. (US1.1-3, US1.5)
      - `test_audit_claude_code_vulnerable_text`: `audit vulnerable_plugin` -> exit 1; output
        contains `CC001` and `SA007` (do not assert on wrapped Rich paths). (US1.4)
      - `test_audit_claude_code_safe`: `audit safe_plugin` (text), `--format json`, and
        `--format json --severity low` -> all exit 0; JSON `findings == []`,
        `files_analyzed == 5`. (US2)
      - `test_audit_claude_code_malformed`: `audit malformed --format json --severity high` -> exit
        1; one `CC000` row, `line == 3`, `file` ends with `broken.md`, `agent is None`,
        `tools == []`; no row with `agent == "ok"`; `"ziran-fake-secret-0416" not in stdout`.
        (US4.2)
      - `test_audit_claude_code_secret_redacted`: `tmp_path/agents/leaky.md` with frontmatter
        `name`/`tools: Read` and body line containing `api_key = "ziran-fake-secret-0418"` ->
        `--format json` exit 1, one `SA001` row at the real file line, literal not in stdout.
        (US4.1)
      - `test_audit_claude_code_single_file`: `audit <tmp agent .md with tools: Bash>` ->
        `files_analyzed == 1`; no Python-regex SA003 row from the frontmatter text (only the
        declared-tool `SA003` with `tools == ["Bash"]`). (FR-002)
      - `test_audit_mixed_python_and_agents`: `tmp_path/agent.py` with the SA001 literal from 036
        plus `tmp_path/.claude/agents/a.md` (`tools: Read, WebFetch`) -> Python `SA001` row with
        `agent is None` and `tools == []` comes before the `CC001` row. (US3.2)
      - `test_audit_json_python_keys_unchanged`: `tmp_path/agent.py` only -> rows keep exactly the
        five 036 keys. (US3.1)
      - `test_audit_wuwei_agents_dir_widening`: `tmp_path/agents/builder.md` with `tools: Read, Grep`
        exits 0 in `--format json --severity high` with no CC001; rewriting it to
        `tools: Read, Grep, WebFetch` exits 1 with a critical CC001 row naming `builder` and
        `Read -> WebFetch`. (US5)
      Confirm they fail (Claude Code files not audited today).
- [ ] T008 Implement the `audit` wiring in `ziran/interfaces/cli/main.py` per plan §4: local
      `scan = load_claude_code(target)`, file/dir branches, merge, `row |= {"agent", "tools"}` only
      when `scan.detected`; docstring: mention Claude Code plugins, `.claude/agents/` and `agents/`
      and add `ziran audit ./my-plugin/ --format json --severity high`. Do not modify
      `_display_audit_report`. T007 passes.
- [ ] T009 Regression: all pre-existing `TestAuditCommand`, `test_static_analysis.py` and
      `test_chain_analyzer.py` tests pass unmodified (US3.1, SC-002).

## Phase 4 — Docs (FR-011)

- [ ] T010 `docs/reference/cli.md`, `ziran audit` section: "Claude Code plugins" subsection with
      detection rules (plugin root, `.claude/agents/`, a directory named `agents`, a single agent
      `.md`), the rule table from plan §3 (rule, severity, what, line), the Claude Code JSON row
      example with `agent`/`tools` and when those keys appear, and "exit codes unchanged". Note
      that SARIF for `audit` is not provided yet.

## Phase 5 — Gates

- [ ] T011 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Revert any `uv.lock` drift before committing. Commit
      `feat(audit): audit Claude Code plugins with static checks and declared-tool chains`; PR
      against `develop` linking #418; check `gh pr checks` until green.

## Dependencies
T001 -> T002; T003 before T005; T002 + T003 + #416 -> T004 -> T005 -> T006 -> T007 -> T008 -> T009
-> T010 -> T011. T001 and T003 can run in parallel.
