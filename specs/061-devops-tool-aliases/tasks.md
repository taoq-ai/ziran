# Tasks: map read_secrets and execute_command to existing chain capabilities

Base: `develop` @ 8943b83. Test first: run each test task and see it fail before the
implementation task. Existing tests are not modified, only extended.

## Phase 1 - Aliases (FR-001, FR-002; US1, US2, US3)

- [x] T001 Extend `test_canonical_tool_name` in `tests/unit/test_tool_aliases.py` with the US1
      cases, and add `test_devops_tools_give_secret_to_execution_chain` for US2. Run
      `uv run pytest tests/unit/test_tool_aliases.py` and see the eight new mapped and chain
      cases fail.
- [x] T002 Add `readsecrets` and `executecommand` to `_FRAMEWORK_ALIASES`. T001 passes, and
      `tests/unit/test_chain_analyzer.py` and `tests/unit/test_chain_patterns.py` pass unchanged.

## Phase 2 - Docs and gates (FR-003, FR-004; SC-003)

- [x] T003 List both names in `docs/concepts/tool-chains.md` after the RAG table.
- [x] T004 Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
      `uv run pytest --cov=ziran`.

## Phase 3 - Study checks outside this repository (US4; SC-004)

- [x] T005 Run ziran-paper `study/scripts/p5.py --side dev` at 8943b83 and at the branch head:
      gt_fw_tp_002#0 moves from missed to found, no other dev chain moves.
- [x] T006 Run ziran-paper `study/scripts/dev_benchmark.py run` at both heads: same counts.
      Compare chains on every agent a dev scenario names: only vulnerable_agentcore_devops
      changes.
