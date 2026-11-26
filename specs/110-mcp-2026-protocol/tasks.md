# Tasks: the MCP client speaks the 2026-07-28 protocol

- [x] T001 Write the fake MCP servers (modern-only, legacy 2025-11-25 with sessions, 2024-11-05)
  in `tests/mcp_servers.py` and the failing tests in `tests/unit/test_mcp_versions.py` and
  `tests/integration/test_mcp_versions_scan.py`; run red (20 failed, 3 passed).
- [x] T002 Negotiation, `_meta`, headers, SSE and error parsing in `mcp_handler.py`.
- [x] T003 `input_required` follow: record, flag, decline, retry once.
- [x] T004 Auto-detection probe in `http_adapter.py` uses the handler's health check.
- [x] T005 Check that a scan which measured nothing says so: already true (spec 082); pinned by
  two scan tests.
- [x] T006 Update the old-contract fake in `tests/unit/test_protocol_handlers.py` (answer the
  `notifications/initialized` notification) and the remote-agent docs.
- [x] T007 Run the touched tests green, `ruff check`, `ruff format --check`, `mypy ziran/`.
