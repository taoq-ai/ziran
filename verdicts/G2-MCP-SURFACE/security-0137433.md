Verdict: PASS
Gate: security
Item: G2-MCP-SURFACE
PR: taoq-ai/ziran#505
Head: 0137433d92cb61bbee5e740a373779b33370f26d
Confidence: high

## Findings
- [low] tests/integration/test_mcp_hostile_server.py:517 blocks: no. The sweep's "explained" prefixes are broad (`Request `, `Response for `, `Tool '`, `Warning: `), and it reads two modules only. A future SDK log call that starts with one of those prefixes and quotes content would pass the sweep. This is moot under the `<2` cap while 1.30.0 is the last 1.x release; recheck on any mcp 1.31.
- [low] ziran/interfaces/cli/mcp_hostile_server.py:98 blocks: no. `tmp.write_text` follows a symlink planted at `mcp_hostile_record.tmp` in a shared record folder (CWE-59). Unchanged; the existing atomic-write pattern.
- [low] blocks: no. Up to 2000 characters of sampling text are kept, and a host that honours `includeContext: allServers` may include other servers' context. This is by design and stated in the guide.

## Probes
- Fix diff 84d5d4d on 2736594:
  - `_RECEIVE_LOG_CALLS` gains the 4 session templates plus "Response ID" and "Uncaught exception in notification handler";
  - the filter is installed on `mcp.server.lowlevel.server` and on the root logger;
  - the `mcp.shared.session` install is gone;
  - raw stdio tests cover a notification and a request at the default level and `-v`;
  - an ast sweep test reads the installed SDK.
- 0137433 merges develop (#507) and touches none of the mcp-hostile files (`git diff 84d5d4d 0137433` on them is empty). The PR diff against develop's tip d61eed8 is 29 files; uv.lock has 0 version or hash lines.
- Fresh `git archive 0137433` copy with a uv venv holding mcp 1.30.0. Only the touched test files were run: test_mcp_hostile_server.py and test_mcp_server_surface.py, 70 passed under `timeout 120`.
- Raw JSON-RPC stdio client with `--log-file` and key `sk-live-PROBE-SECRET-7Q9Z`, 7 shapes at the default level and at `-v`, each under `timeout 120`, all exit 0:
  - pretty-printed: withheld 10 and 22 (default, `-v`);
  - truncated line: 1 and 4;
  - object `id`: 1 and 4;
  - late accept (`--timeout 1`): 1 and 4;
  - off-schema nested value: 0 and 2 (record error `malformed reply (ValidationError)`);
  - notification: 1 and 3;
  - request: 1 and 4.
- All 14 runs give 0 full-key hits and 0 last-6-character hits across stderr, the log file and the record. The "withheld" counts match between stderr and the log file. ziran's `attack_library_initialized` line prints in every run.
- Each run reached the elicitation: the record shows timeout, or error for off-schema.
- Known-positive: on mutant f6 (the root-logger install removed), the notification and request shapes put the key back, in 1 stderr line and 1 log-file line each.
- Mutants, each in a fresh copy, touched test files only, under `timeout 120`, all killed:
  - f6 (no root install) fails 4 tests: notification and request, default and verbose;
  - r_nolow (no lowlevel install) fails the late-reply test and the 3 malformed-reply tests;
  - dropping "Uncaught exception in notification handler" fails the sweep for server.py;
  - dropping "Failed to validate request" fails the 2 request tests and the session sweep;
  - dropping "Message that failed validation" fails request-verbose and the session sweep;
  - dropping "Failed to validate notification" fails the 2 notification tests and the session sweep;
  - dropping "Unhandled exception in receive loop" fails the session sweep;
  - dropping "Response ID" fails the session sweep.
- Filter scope, in process: one filter each on root and lowlevel after 2 `build_server` calls.
  - Unrelated root records pass unchanged: a WARNING about disk space, and an ERROR via `logging.exception` that keeps its `exc_info`.
  - Named loggers (`ziran.*`, `httpx`) are untouched, even when the text matches a template.
  - A root record that matches a template is rewritten at its own level, never dropped. The cost is that a non-SDK root line starting "Response ID" loses its text.
- SDK sweep beyond the two modules: no other server or shared module on the stdio path logs client content. That covers `fastmcp` (resources and prompts are unused), `experimental/task_result_handler` (message type only), `tool_name_validation` (our tool name) and `transport_security` (HTTP only). `server/session.py` and `server/stdio.py` make no log calls.
- CI, read once with `gh pr checks 505` at 0137433: 21 checks pass, among them test 3.11, 3.12 and 3.13, integration-test, typecheck, lint, dependency-audit, and CodeQL Analyze for python, actions and javascript-typescript.
- Processes: after the probes, `pgrep` finds 0 scratch processes left.
- closed: [medium] form answer sent as a notification or a request logged through the root logger (CWE-532) at 84d5d4d
- still closed (re-run at this head): the late reply, pretty-printed, truncated, object-id and off-schema leaks; the roots spellings; the guide cleanup.
- Confidence high: every shape runs end to end through the shipped CLI at both levels and in both sinks, with a known-positive on the mutant, and all 8 removal mutants are killed.

## Residual risk
The redaction depends on mcp 1.30.0's log templates, and the sweep test guards that only for the two receive-path modules. No `notifications/cancelled` is sent on timeout (a documented limit).
