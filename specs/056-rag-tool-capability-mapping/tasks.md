# Tasks: map RAG-agent tool names to existing chain capabilities

Base: `develop` @ b813e4f. Test first: run each test task and see it fail before the
implementation task. Existing tests are not modified, only extended.

## Phase 1 - Alias map (FR-001, FR-002; US1, US3)

- [ ] T001 Add cases to `tests/unit/test_tool_aliases.py`: the three names, the `tool_` prefix
      form and every variant under spec Assumptions map to `http_request`, `browse_url` or
      `vector_store_read`; `search`, `web_search`, `vector_store_write`, `url_loader` stay
      unchanged. Run `uv run pytest tests/unit/test_tool_aliases.py` and see the new mapping
      cases fail.
- [ ] T002 Add `_FRAMEWORK_ALIASES` and `_framework_alias` to
      `ziran/application/knowledge_graph/tool_aliases.py` and call it at both unchanged-id exits
      of `canonical_tool_name`; widen the module docstring. T001 passes.

## Phase 2 - Chains fire (US2)

- [ ] T003 Add `TestRagToolNames` to `tests/unit/test_chain_analyzer.py` with the five US2
      pairs (ids `tool_<name>`), asserting type, risk and original ids. Run it on the T001-only
      tree state (before T002) to see it fail, then green after T002.

## Phase 3 - Docs and gates (FR-004, FR-005, SC-003)

- [ ] T004 Add a "LangChain-style tool names" section to `docs/concepts/tool-chains.md`.
- [ ] T005 Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran`.
