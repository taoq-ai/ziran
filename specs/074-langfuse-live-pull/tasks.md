# Tasks: Langfuse live trace pull

- [ ] T001 Write the API-mode tests (mock transport, CLI) and the TOOL-observation tests; run red.
- [ ] T002 Replace `_ingest_api` with the httpx pull: keys, host, since, session, pages, 429.
- [ ] T003 `_parse_trace`: `TOOL` type and JSON-string `input`.
- [ ] T004 Incremental cursor: load, skip seen, `save_cursor` atomic, no key in the file.
- [ ] T005 `AnalyzerService.analyze_sessions` / `emit_session_findings`; CLI pulls once.
- [ ] T006 CLI flags `--session-id`, `--incremental`; save the cursor after report and alerts.
- [ ] T007 Replace the old SDK ImportError test.
- [ ] T008 Docs section and `examples/28-langfuse-live-analysis/`.
- [ ] T009 Run ruff, ruff format --check, mypy and the suite with coverage.
