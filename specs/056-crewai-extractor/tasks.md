# Tasks: static CrewAI project reader for `ziran audit`

Test-first: each implementation task follows a test task that is run and seen failing first. New
unit test files carry `@pytest.mark.unit`; tests added to `tests/unit/test_cli_main.py` follow that
file (no markers). Names, keys and messages are those in [plan.md](plan.md#public-contract).

## Phase 1: shared chain construction (FR-008, US5.2)

- [x] T001 Failing test in `tests/unit/test_claude_code_audit.py`: `tool_chains([])` is `[]`;
      `tool_chains(["FileReadTool", "send_email"])` holds a `data_exfiltration` chain; for a
      Claude Code agent, `agent_chains(agent)` equals `tool_chains(agent.effective_tools)`.
- [x] T002 Extract `tool_chains(tools)` in `claude_code_audit.py`; `agent_chains` calls it.
      Existing tests pass unmodified.

## Phase 2: domain models (FR-004 to FR-006)

- [x] T003 [P] Failing tests in `tests/unit/test_crewai_project.py` for `CrewAIAgent.tools`
      (order, de-duplication, empty) and `CrewAIScan.detected`.
- [x] T004 Add `ziran/domain/entities/crewai.py`.

## Phase 3: loader (FR-001 to FR-007, US2, US3)

- [x] T005 Failing loader tests in `tests/unit/test_crewai_project.py` with `tmp_path` projects:
      discovery (directory, agents.yaml file target, agents.yaml without tasks.yaml, skip dirs,
      several projects), YAML tools, crew.py precedence, config-key mapping, task assignment by
      YAML and by `agent=`, crew.py-only task, tool-name forms, union order, empty tool set.
- [x] T006 Failing hostile-input tests: import marker never written, syntax error, null byte,
      oversized file, deep AST, deep YAML, invalid and non-mapping YAML, non-mapping entries,
      bad `tools` values, non-literal `tools=`, unsupported elements, unresolvable `agent=`,
      symlink escape, undecodable bytes; no message contains a planted file-content string.
- [x] T007 Implement `ziran/infrastructure/config/crewai_project.py` until T005 and T006 pass.
- [x] T007a Failing tests for FR-007 as revised (US3.8, US3.9): a simple assignment resolves to
      the callee, two callees or a non-call binding stay as written, other elements are kept as
      source text with no error. Then resolve names and unparse other elements in the loader.

## Phase 4: audit use case (FR-009)

- [x] T008 Failing tests in `tests/unit/test_crewai_audit.py`: CR000 per scan issue and per unit
      error, CR001 per chain with file, line, agent, tools and message; no findings for a clean
      unit; order.
- [x] T009 Implement `ziran/application/static_analysis/crewai_audit.py`.

- [x] T009a Failing test in `tests/unit/test_crewai_audit.py`: a unit over `MAX_UNIT_TOOLS` gets
      one CR000 at its entry line and no CR001; a unit at the bound gets its chains. Then add the
      bound in `crewai_audit.py` (FR-009).

## Phase 5: CLI (FR-010, US1, US5.1)

- [x] T010 Fixtures `tests/fixtures/crewai/vulnerable_crew` and `tests/fixtures/crewai/safe_crew`
      (src layout: `src/<pkg>/crew.py`, `src/<pkg>/config/{agents,tasks}.yaml`).
- [x] T011 Failing CLI tests in `TestAuditCommand`: vulnerable JSON (exit 1, CR001 row, `crewai`
      units), vulnerable text (exit 1 on the critical chain, `CR001` printed), safe JSON
      (exit 0, units listed, no CR001), agents.yaml file target, no `crewai` key without a
      project.
- [x] T012 Wire `load_crewai` and `audit_crewai` into `audit` in `ziran/interfaces/cli/main.py`.

## Phase 6: sampler (FR-011, US4)

- [x] T013 Failing tests in `tests/unit/test_sample_crewai_units.py`: same seed same output,
      fewer units than `--n`, errored units left out and counted, missing `crewai` key exits 2.
- [x] T014 Implement `scripts/sample_crewai_units.py`.

## Phase 7: docs and gates (FR-012, SC-004)

- [x] T015 Add the CrewAI section to `docs/reference/cli.md`.
- [x] T016 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran`.

## Phase 8: fix round 1

- [x] T017 Uncalled attribute tool elements kept as source text (`self.search`); US3.4, US3.9,
      FR-007 and the cli.md paragraph updated; chains pinned unchanged.
- [x] T018 `RecursionError` from `ast.unparse` while walking crew.py becomes a crew.py error on
      every unit (nested-dict test under `MAX_AST_DEPTH`).
- [x] T019 YAML `ValueError` (impossible date, integer over the digit limit) becomes a file error.
- [x] T020 YAML aliases refused in agents.yaml and tasks.yaml; 64-tool assumption revised.
- [x] T021 Tests pin the crew.py lookup order, the unwalked symlinked directory and the file-target
      root; a config-directory PATH reads `config/../crew.py`.

## Dependencies

T001 -> T002. T003 -> T004 -> T005/T006 -> T007 -> T008 -> T009 -> T010/T011 -> T012.
T013 -> T014 needs only the JSON shape from plan.md section 5. T015 after T012.
