# Tasks: map RAG-agent tool names to existing chain capabilities

Base: `develop` @ b813e4f. Test first: run each test task and see it fail before the
implementation task. Existing tests are not modified, only extended.

## Phase 1 - Alias map (FR-001, FR-002; US1, US3)

- [x] T001 Add cases to `tests/unit/test_tool_aliases.py`: the three names, the `tool_` prefix
      form and every variant under spec Assumptions map to `http_request`, `browse_url` or
      `vector_store_read`; `search`, `web_search`, `vector_store_write`, `url_loader` stay
      unchanged; `Read(notes/tavily_search.md)` stays `read_file` and
      `mcp__tavily__send_tavily_search_digest` stays `send_email` (FR-002 precedence). Run `uv run pytest tests/unit/test_tool_aliases.py` and see the new mapping
      cases fail.
- [x] T002 Add `_FRAMEWORK_ALIASES` and `_framework_alias` to
      `ziran/application/knowledge_graph/tool_aliases.py` and call it at the non-Claude-Code
      unchanged-id exit of `canonical_tool_name`; widen the module docstring. T001 passes.

- [x] T006 Anchor the match (review fix): add cases where an id contains a name next to other
      words (`shell_execute_tavily_search`, `vectorstore_search_database`,
      `vector_store_query_writer`, `save_vectors_to_research_db`, `Foo(tavily_search)` and
      others) and stays unchanged, plus chain cases `Agent -> shell_execute_tavily_search`
      (`delegation_to_rce`) and `tool_read_file -> send_email_tavily_search`
      (`data_exfiltration`). See them fail on the substring match, then anchor
      `_framework_alias`.
- [x] T007 Leave MCP ids unmapped (review fix): add cases `mcp__send_email__tavily_search`,
      `mcp__shell_execute__tavily_search`, `mcp__tavily__tavily_search` and
      `mcp__tavily__tavily-search` staying unchanged, plus chain case
      `tool_read_file -> mcp__send_email__tavily_search` (`data_exfiltration`). See them fail on
      the MCP prefix stripping, then remove `_MCP_PREFIX` and the MCP-branch call.

## Phase 2 - Chains fire (US2)

- [x] T003 Add `TestRagToolNames` to `tests/unit/test_chain_analyzer.py` with the five US2
      pairs (ids `tool_<name>`), asserting type, risk and original ids. Run it on the T001-only
      tree state (before T002) to see it fail, then green after T002.

## Phase 3 - Docs and gates (FR-004, FR-005, SC-003)

- [x] T004 Add a "LangChain-style tool names" section to `docs/concepts/tool-chains.md`.
- [x] T005 Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      and the CI unit job `uv run pytest -m "not integration" --cov=ziran` (no integration
      test references the mapped names).
