# Tasks: an MCP target that takes no chat prompt is unmeasured

Base: `origin/develop` @ eaf2ee5. Branch `fix/082-mcp-send-unmeasured`. Test first: T001 to T003
run red before T004.

## Phase 1 - Tests (US1, US2)

- [x] T001 `tests/unit/test_protocol_handlers.py`: a no-chat server sees only
      `completion/complete`, never `sampling/createMessage`, and two sends log one warning.
- [x] T002 `tests/unit/application/test_attack_executor.py`: the placeholder is an error
      sentinel; a one-prompt vector skips the detectors, has `prompt_errors` 1, reads unmeasured
      and is not cacheable; a multi-turn vector likewise.
- [x] T003 `tests/integration/test_mcp_no_chat_scan.py`: 10 vectors through `AgentScanner` and a
      real `HttpAgentAdapter`: breaker closed, one warning, empty scan cache, ten unmeasured ids,
      markdown and HTML read INCOMPLETE and never PASSED.

## Phase 2 - Fix (FR-001 to FR-005)

- [x] T004 `mcp_handler.py`: drop `sampling/createMessage`, warn once.
- [x] T005 `attack_executor.py` and `tactics.py`: sentinel and `outcome: unmeasured`.
- [x] T006 `result_builder.py`: list unmeasured ids; `phase.py` docstring.

## Phase 3 - Docs and gates

- [x] T007 One line in `docs/guides/remote-agents.md`.
- [x] T008 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, the
      touched test files under `timeout 120`; the full suite and coverage come from CI.
- [ ] T009 Open the draft PR to `develop`.
