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
- [x] T012 Run ruff, ruff format --check, mypy, pytest --cov and the benchmark checks.
- [x] T013 Keep every reply per vector so an earlier leak survives a later careful reply;
  count a whitespace-only elicited value as blank. Mutants of both run red.
- [x] T014 Fix round 1 (gates at bdd2079): an unmeasured result reads INCOMPLETE in terminal,
  markdown and HTML and stays out of the OWASP and ATLAS tables; trust counts measured passes;
  `ziran ci` fails a run with nothing measured; late replies logged without content; malformed
  replies stored as their error type; roots normalised, case-folded, credential descendants;
  tests for the dry-run count, decline with content, include_context, never-called exit.
- [x] T015 Fix round 2 (security at 006161d): key the log filter on the SDK's receive-path
  calls ("Received message", "Received exception from stream") and clear args and exc_info;
  raw stdio tests for a pretty-printed, truncated and object-id reply; `ziran ci` warns on a
  partial run in the console and step summary; a shared metadata key constant.
- [x] T016 Fix round 3 (security at 2736594): add the session's four content-quoting calls and
  two more the sweep found; install the filter on the root logger, where `shared/session.py`
  logs, and drop the dead `mcp.shared.session` install; raw stdio tests for a form answer sent
  as a notification and as a request at default and -v; an SDK log-call sweep test.
