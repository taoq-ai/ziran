# Tasks: ziran init Scaffolding Command

## Phase 2: Foundational

- [ ] T001 Create `ziran/interfaces/cli/init_command.py` with the `init` click command, config generation, YAML writing, and Rich next-steps panel
- [ ] T002 Register the `init` command in `ziran/interfaces/cli/main.py` via `cli.add_command(init)`

## Phase 3: User Story 1+2+3 — Tests

- [ ] T003 [P] [US1] Create `tests/unit/test_cli_init.py` with tests for interactive init, overwrite protection, non-interactive mode, YAML validation

## Phase 4: Polish

- [ ] T004 Run quality gates (ruff check, ruff format, mypy, pytest)
