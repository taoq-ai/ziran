Verdict: FIX
Gate: security
Item: G2-MCP-SURFACE
PR: taoq-ai/ziran#505
Head: 2736594e28c6d93d2afa05d5e567a2ea8893823d
Confidence: high

## Findings
- [medium] ziran/infrastructure/mcp_hostile/server.py:122 blocks: yes. Failure: a client that answers the elicitation form with a notification or a request instead of a response still gets the typed key logged on stderr and in `--log-file` at the default level. Examples: `{"method":"notifications/elicitation/response","params":{"action":"accept","content":{"api_key":"<key>"}}}`, or the same body as a request. In mcp 1.30.0, `mcp/shared/session.py` logs through the root logger (`logging.warning(...)` at lines 383, 384, 430 and 444; the module has no named logger). The filter is installed on the never-used `mcp.shared.session` logger, so it never sees these records: "Failed to validate notification: ... Message was: ... 'api_key': '<key>'" (WARNING, full key); "Failed to validate request: ..." (WARNING, the key's tail through pydantic's `input_value`); and "Message that failed validation: ..." (DEBUG, the full key). The `mcp.shared.session` install that 13fb4b5 added therefore covers nothing, and the guide's "never its content" does not hold for these shapes (CWE-532). Verified fix: add the four session templates to `_RECEIVE_LOG_CALLS` and install the filter on `logging.getLogger()` as well.
- [low] ziran/interfaces/cli/mcp_hostile_server.py:98 blocks: no. `tmp.write_text` follows a symlink planted at `mcp_hostile_record.tmp` in a shared record folder (CWE-59). Unchanged; the existing atomic-write pattern.
- [low] blocks: no. Up to 2000 characters of sampling text are kept; a host that honours `includeContext: allServers` may include other servers' context. This is by design and stated in the guide.

## Probes
- Fresh `git archive 2736594` copy with a uv venv holding mcp 1.30.0. 108 tests pass (mcp surface unit, hostile-server integration, cicd).
- PR diff against merge-base 4d26d62 (develop's tip): 29 files, the 071 changes only. The uv.lock delta has 0 version or hash lines.
- Raw JSON-RPC stdio client with `--log-file` and key `sk-live-PROBE-SECRET-7Q9Z`, each shape run at the default level and at `-v`. Counts are the full key / its last 6 characters / "withheld":

| Shape | stderr | log file | record | withheld (default, -v) |
|---|---|---|---|---|
| pretty-printed | 0/0 | 0/0 | 0 | 10, 22 |
| truncated line | 0/0 | 0/0 | 0 | 1, 4 |
| object `id` | 0/0 | 0/0 | 0 | 1, 4 |
| late accept (`--timeout 1`) | 0/0 | 0/0 | 0 | 1, 4 |
| off-schema nested value | 0/0 | 0/0 | 0 | 0, 2 (record error `malformed reply (ValidationError)`) |
| notification | 1/1 | 1/1 | 0 | 0, 2 |
| request (default) | 1/1 | 1/1 | 0 | 0 |
| request (`-v`) | 2/2 | 2/2 | 0 | 2 |

- Every run reached the elicitation: the record shows timeout or error for the vector.
- Leaking lines carry logger `root`. Notification at WARNING: "Message was: method='notifications/elicitation/response' params={'action': 'accept', 'content': {'api_key': 'sk-live-PROBE-SECRET-7Q9Z'}}". Request: the WARNING carries `input_value={'action': 'accept', 'con...ive-PROBE-SECRET-7Q9Z'}}`, and the DEBUG line carries the full params.
- SDK sweep of mcp 1.30.0, every log call outside `client/` and `cli/`:
  - The content-quoting calls are `lowlevel/server.py:682` and `:713` (filtered) and `shared/session.py:383`, `:384`, `:430` and `:444` (root logger, unfiltered). `shared/session.py:478` quotes only a client-chosen string id.
  - `server/session.py` and `server/stdio.py` make no log calls.
  - `lowlevel/server.py:723` logs warnings caught during handling; nothing in this tool path warns.
- Differential, head against mutant f6 (the `mcp.shared.session` install removed), over all 7 shapes at the default level: 0 differences in key hits or withheld counts. f6 also survives the test suite (236 passed), so the install has no effect.
- Fix check: a copy with the four session templates added and the filter also installed on the root logger gives 0 hits for notification and request at both levels. "withheld" appears 1 to 4 times, and ziran's own log lines are still emitted.
- Filter mutants, each in a fresh copy:
  - f1 (drop "Received exception from stream") and f4 (`return False`) fail the late-reply test and all 3 malformed-reply tests;
  - f2 (drop "Received message") and f3 (keep `exc_info`) fail `test_the_filter_withholds_args_and_exc_info_of_receive_logs`;
  - f5 (no install) fails the late-reply and malformed-reply tests.
- Unrelated records: the head's direct filter test checks that an unrelated record keeps its message and `exc_info`. The filter returns True, so it drops nothing.
- closed: [medium] pretty-printed, truncated or object-id reply logged through "Received exception from stream" (CWE-532) at 13fb4b5
- still closed from 006161d (re-run at this head): the late reply, the off-schema accept and the roots spellings.
- Confidence high: every count comes from the shipped CLI over stdio, with known-negative shapes, a differential against the mutant, and a verified fix.

## Residual risk
The open path needs a nonconforming client that sends the form answer as a notification or a request; conforming hosts send a response, which the head withholds. No `notifications/cancelled` is sent on timeout, a documented limit.
