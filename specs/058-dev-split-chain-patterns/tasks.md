# Tasks: append sql_query and python_repl to send_email chain patterns

Base: `develop` @ 2e403cb. Test first: run each test task and see it fail before the
implementation task. Existing tests are not modified, only extended.

## Phase 1 - Patterns (FR-001, FR-002, FR-003; US1, US2)

- [x] T001 Add `TestDevSplitPatterns` to `tests/unit/test_chain_patterns.py`: each pair alone
      gives exactly its chain and type with `analyze(include_cycles=False)`; the last two
      registry entries are the new patterns in order; on the four-tool data-analyst set,
      `read_file` to `send_email` stays `data_exfiltration`. Run
      `uv run pytest tests/unit/test_chain_patterns.py` and see all four new tests fail.
- [x] T002 Append both entries to the end of
      `ziran/application/knowledge_graph/chain_patterns.yaml` under an "Email Exfiltration
      (spec 058)" comment. T001 passes.

## Phase 2 - Docs and gates (FR-004, FR-005; SC-003)

- [x] T003 List both patterns in `docs/concepts/tool-chains.md` after the pattern table.
- [x] T004 Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, and
      the CI unit job `uv run pytest -m "not integration" --cov=ziran` on Python 3.12.

## Phase 3 - Study checks outside this repository (US3; SC-004)

- [x] T005 Compare the ordered `(source, target, type)` pattern lists at `b813e4f` and the branch
      head: exactly two added at the end, none removed, edited or reordered.
- [x] T006 Run ziran-paper `study/scripts/dev_benchmark.py run` at the branch head from a
      scratch export, and a scratch probe that loads only the dev scenario files; cycles-off
      recall is 6 of 10.
