# Tasks: allowlist baseline so CI fails when an agent's tools widen

Prerequisite: #418 (`038-audit-claude-code-plugins`, on top of #416) merged into `develop`; rebase
this branch on it before T002 (it provides `agent_chains`, `audit_claude_code`,
`StaticFinding.agent` / `.tools`, the `scan` / `report` locals in `audit()` and the fixtures under
`tests/fixtures/claude_code/`). Do not modify #416's or #418's files or fixtures, other than the
`audit()` additions in plan §3.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM. New unit tests carry `@pytest.mark.unit`;
tests added to `tests/unit/test_cli_main.py` follow that file (no markers). Names, messages, file
format and JSON keys are exactly those in [plan.md §Public contract](plan.md#public-contract).
Tests that edit an agent copy the fixture plugin to `tmp_path` first (`shutil.copytree`).

Shared test helper (in each test file, not a new module): a WUWEI-like agent
`agents/builder.md` = `"---\nname: builder\ndescription: Builds.\ntools: Read, Glob, Grep, Bash,
Write, Edit\n---\nBuild things.\n"` (`tools` on line 4).

## Phase 1 — Models and `build_baseline` (FR-002, FR-003, US1)

- [x] T001 [P] Failing tests in `tests/unit/test_claude_code_baseline.py` (new), in-memory
      `ClaudeCodeAgent` / `ClaudeCodeScan`:
      - `build_baseline(scan)` for agents `researcher` (`Read, Grep, WebFetch,
        mcp__slack__send_message`) and `generalist` (no `tools`) -> `version == 1`, agent keys
        `["generalist", "researcher"]` (sorted), `researcher.tools` verbatim, `generalist.tools is
        None`, `researcher.chains` sorted by `tools` and containing
        `BaselineChain(tools=["Read", "WebFetch"], vulnerability_type="data_exfiltration",
        severity="critical")`; `generalist.chains` contains `tools == ["Bash"]`.
      - `model_dump_json(indent=2)` of two builds of the same scan is identical, and does not
        contain the agents' `system_prompt` or `description` text.
      - `AuditBaseline.model_validate_json` rejects: missing `version`, `version: 2`, an unknown
        top-level key, an unknown agent key, `tools: "Read"`, a chain with `tools: []`; accepts
        `{"version": 1, "agents": {}}` and `tools: null`.
      Confirm they fail (`ModuleNotFoundError`).
- [x] T002 Implement `ziran/application/static_analysis/claude_code_baseline.py`: the four models
      and `build_baseline` per plan §1-§2 (module docstring: purpose, rule table, "never serialise
      a scan wholesale"). T001 passes; mypy strict clean.

## Phase 2 — `apply_baseline` (FR-004..FR-006, US2-US4)

- [x] T003 Failing tests in `tests/unit/test_claude_code_baseline.py` for
      `apply_baseline(findings, scan, baseline)`, with `findings =
      audit_claude_code(scan).findings` (#418) and `baseline = build_baseline(<earlier scan>)`:
      - Unchanged scan -> no `CC001`, `SA003`, `SA004`, `SA007` rows; no `BL*`; narrowings `[]`.
      - Builder + `WebFetch` -> `BL001` `(WebFetch,)` with the exact message, `line_number == 4`,
        `severity == "critical"`, `agent == "builder"`; `BL003` rows exactly for the new chains
        (includes `("Read", "WebFetch")` with message
        `"Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch not in the
        baseline"`); no row for accepted `Bash` (`SA003`) or `("Bash", "Write")`; the unaccepted
        `SA003` for `WebFetch` is kept; order: kept findings, then BL001, then BL003.
      - Researcher minus `WebFetch` -> no `BL*`; narrowings `[tool_removed ["WebFetch"],
        chain_removed ["Grep", "WebFetch"], chain_removed ["Read", "WebFetch"]]` (baseline order).
      - Builder without `tools` key -> one `BL002` (`tools == ()`, `line_number == 1`), no `BL001`,
        `BL003` for the inherited chains; `SA007` kept (baseline was restricted).
      - Recorded unrestricted, now `tools: Read` -> `tools_key_added` narrowing, no `BL*`,
        `SA007` gone.
      - New agent `helper` (`Read`) -> `BL004` with `tools == ("Read",)`.
      - Baseline agent absent from the scan -> `agent_removed` narrowing, no `BL*`.
      - Baseline with one chain deleted -> exactly one `BL003` for it, no `BL001`.
      - `CC000` input row -> returned with `severity == "critical"`; a Python `SA001` row and an
        agent `SA001` row -> unchanged; the input list is not mutated.
      - `Bash` recorded, `Bash(npm test:*)` declared -> `BL001` for `Bash(npm test:*)` and a
        `tool_removed` narrowing for `Bash`.
- [x] T004 Implement `apply_baseline` per plan §1 (kept-findings filter, violations, narrowings,
      fixed recommendations, `dataclasses.replace` for `CC000`). T003 passes.

## Phase 3 — CLI (FR-001, FR-007..FR-009, US1-US6)

- [x] T005 Failing tests in `tests/unit/test_cli_main.py`, new class `TestAuditBaseline`
      (`CliRunner`, JSON parsed from `result.stdout`):
      - US1: `--write-baseline B` over a `tmp_path` copy of `vulnerable_plugin` -> exit `0`, file
        content per spec US1.1, stdout JSON has `"baseline": {"narrowed": []}` and `findings == []`
        with `--format json` and with `--format json --severity low`; a second write is
        byte-identical.
      - US2 (WUWEI): `tmp_path/agents/builder.md`; write baseline; append `, WebFetch` to the
        `tools` line; `--baseline B --format json` -> exit `1`, rows `BL001` (`tools ==
        ["WebFetch"]`, `line == 4`, `agent == "builder"`) and `BL003` (`tools == ["Read",
        "WebFetch"]`, message contains `Read -> WebFetch`); same with `--severity critical` ->
        exit `1`; text mode -> exit `1` and stdout contains `builder`, `WebFetch`,
        `Read -> WebFetch`.
      - US3: researcher without `WebFetch` -> JSON exit `0`, no `BL*` row, `baseline.narrowed`
        contains `{"agent": "researcher", "change": "tool_removed", "tools": ["WebFetch"]}`; text
        mode exit `0` and stdout contains `researcher`, `tool_removed`, `WebFetch`; JSON
        `--severity low` exit `0`.
      - US4: `tools` key removed -> `BL002` exit `1`; new agent file -> `BL004` exit `1`; chain
        deleted from `B` -> one `BL003` exit `1`; `tests/fixtures/claude_code/malformed` with a
        baseline written from it (that write itself exits `1`) -> text exit `1`, JSON `CC000` row `severity == "critical"`,
        `ziran-fake-secret-0416` not in stdout.
      - US5: both flags -> exit `2`; `--baseline` to a missing file -> exit `2`; `B` = `"{not
        json ziran-fake-secret-0419"` -> exit `2` and `ziran-fake-secret-0419` not in
        `result.output`; `B` = `{"agents": {}}` -> exit `2`; `--baseline` or `--write-baseline`
        over a `tmp_path` holding only `agent.py` -> exit `2` and no file written.
      - US6: a Claude Code run and a Python-only run without the flags have no `baseline` key
        (existing `TestAuditCommand` tests stay unmodified and green).
- [x] T006 Implement plan §3 in `ziran/interfaces/cli/main.py`: the two options, the
      mutual-exclusion check, the baseline block after #418's merge block and before the
      `--severity` filter, the `baseline` JSON key, the text panel (escaped), and a docstring
      example (`ziran audit ./agents/ --baseline allowlist.json`). T005 passes; full
      `tests/unit/test_cli_main.py` passes.

## Phase 4 — Docs (FR-011)

- [x] T007 `docs/reference/cli.md`, `ziran audit`: add `--baseline` / `--write-baseline` to the
      option table and an "Allowlist baseline" subsection after #418's "Claude Code plugins"
      subsection: the record/commit/check loop, the file format (plan §2 example), the BL rule
      table with exact messages, what a baseline accepts (CC001, SA003/SA004/SA007 for recorded
      grants) and never accepts (SA001, Python findings, parse issues, which become critical), the
      `baseline.narrowed` JSON key, and exit codes (widening -> `1` under every `--severity`,
      narrowing -> no effect, misuse -> `2`). Note the out-of-scope allowlist proposal is not
      provided.

## Phase 5 — Gates

- [x] T008 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift. Commit
      `feat(audit): allowlist baseline so CI fails when an agent's tools widen` (no `!`, no
      `BREAKING CHANGE`, no `Co-Authored-By`); PR to `develop` linking #419.

## Dependencies
T001 -> T002 -> T003 -> T004 -> T005 -> T006 -> T007 -> T008. T001 can be written before #418
merges (against the 037/038 contracts), but every task from T002 on imports #418's
`agent_chains`, so run them after rebasing on `develop` with #418.
