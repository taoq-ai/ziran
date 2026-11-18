# Tasks: the MCP server-initiated attack surface

- [x] T001 Rerun the spike against a sampling-capable host (fast-agent 0.10.57, passthrough
  model) and record the result in spec.md.
- [x] T002 Add the `mcp` extra, include it in `all`, relock, add `mcp.*` to the mypy overrides.
- [x] T003 Write the unit tests (domain, library exclusion, scoring) and run them red.
- [x] T004 Add `McpServerRequest`, `McpServerReply` and `AttackVector.mcp_server_request`.
- [x] T005 Parse the block in the library and drop it from `get_attacks_for_phase`.
- [x] T006 Add `mcp_server_surface.yaml` with eight vectors, two per sub-family.
- [x] T007 Write `score_reply` and `build_campaign_result`.
- [x] T008 Write the integration tests (in-memory server, stdio CLI, `ziran report`), run red.
- [x] T009 Write the hostile server and the `mcp-hostile-server` command; register it.
- [x] T010 Skip server-surface vectors in the scan dry-run count.
- [x] T011 Write the guide, add it to `mkdocs.yml`, regenerate the coverage docs and refresh the
  baseline.
- [ ] T012 Run ruff, ruff format --check, mypy, pytest --cov and the benchmark checks.
