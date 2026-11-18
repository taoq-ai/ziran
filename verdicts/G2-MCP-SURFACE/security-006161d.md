Verdict: FIX
Gate: security
Item: G2-MCP-SURFACE
PR: taoq-ai/ziran#505
Head: 006161dbdebea5613bd8fb0d0080b0e50da1ba68
Confidence: high

## Findings
- [medium] ziran/infrastructure/mcp_hostile/server.py:101 blocks: yes. Failure: an elicitation reply whose stdio line is not a valid JSON-RPC message still reaches the log with its content. Such lines include a reply pretty-printed across several lines, a truncated line, or one with an object as `id`. The SDK's stdio reader passes the pydantic error into the stream, `mcp.server.lowlevel.server` logs `Received exception from stream: ... input_value='<the raw line>'` at ERROR, and the filter rewrites only messages containing "unknown request ID". A pretty-printed accept therefore logs the line `"api_key": "<typed key>"` in full on stderr and in `--log-file`. A truncated line or a bad id logs the line's last ~25 characters, enough for a whole OTP code or the end of a key. This is the sibling of the late-reply path the fix closed (CWE-532). Suggested fix: the filter also reduces any "Received exception from stream" record to the exception type.
- [low] ziran/infrastructure/mcp_hostile/server.py:101 blocks: no. The filter matches on `getMessage()` only. A record that carried the reply in `exc_info`, or that came from a child logger, would pass unchanged; mcp 1.30.0 (the last 1.x release on PyPI) logs neither, so this guard only matters for a future SDK.
- [low] ziran/interfaces/cli/mcp_hostile_server.py:98 blocks: no. `tmp.write_text` follows a symlink planted at `mcp_hostile_record.tmp` in a shared record folder (CWE-59). Unchanged from the existing atomic-write pattern.
- [low] blocks: no. Up to 2000 characters of sampling text are kept, and a host that honours `includeContext: allServers` may include other servers' context. This is by design and stated in the guide.

## Probes
- Fresh `git archive 006161d` copy with a uv venv holding mcp 1.30.0 (the last 1.x on PyPI). The new and changed tests pass, 59 of them.
- PR diff against merge-base c0a5586: 28 files, and only the 071 changes. The lock delta is the extra metadata alone. `uv lock --check` resolves 213 packages, and the CI pip-audit command with its 7 ignores reports "No known vulnerabilities found, 8 ignored".
- Late reply, stderr and `--log-file`: the real CLI with `--timeout 1` and a client that accepts after 2.5 s with `sk-live-PROBE-SECRET-0042`.
  - Default level: 0 hits in stderr, the log file, the record and the report. One ERROR line per sink reads "a reply arrived after its request timed out (withheld)".
  - With `-v` (DEBUG): 0 hits, and the DEBUG "Received message" line is withheld as well.
- Late reply, known-positive: with the filter call removed in a fresh copy, the key appears in 1 stderr line and 1 log-file line. `test_a_late_form_reply_never_reaches_the_log` fails.
- Off-schema accept: a nested value over stdio leaves 0 hits in the record, the report and stderr, and the error reads `malformed reply (ValidationError)`. A direct `send_request` probe gives False for the error, the record and the campaign. Mutant m14 (exception text put back) fails `test_an_off_schema_accept_is_not_stored`.
- Bad-envelope sibling, run through a raw JSON-RPC client over stdio with `sk-live-PROBE-SECRET-0055` and `--log-file`:
  - pretty-printed reply: the full key in 1 stderr line and 1 log-file line (`input_value='   "api_key": "sk-live-PROBE-SECRET-0055"\n'`);
  - truncated JSON line: the tail `...-PROBE-SECRET-0055"}}` in each sink;
  - object `id`: the tail `...ve-PROBE-SECRET-0055'}}}` in each sink;
  - the record carries 0 hits in all three.
- Filter scope: after 2 `build_server` calls there is 1 filter on each of `mcp.server.lowlevel.server` and `mcp.shared.session`, so it is idempotent.
  - Unrelated ERROR records pass unchanged at their own level: "Received exception from stream: disk full", "Uncaught exception in handler", and a `logger.exception` that keeps its `exc_info`.
  - The filter always returns True, so it drops nothing; it only rewrites messages that contain "unknown request ID".
  - A child logger's record passes unfiltered (a note only).
- Roots, 25 spellings, all as expected: `.ssh/keys`, `.aws/sso`, `.SSH/Keys`, `proj/../..`, `proj/../.aws/sso`, `users/ALICE`, `file:////Users/alice` and `.config/gcloud/legacy` are findings; `.sshkeys`, `.config/other`, `Projects/App` and `https:` pass.
- Mutants, each in a fresh copy, all killed:
  - m11 (drop the descendant match) fails `test_a_root_inside_a_credential_folder_is_a_finding[.../.ssh/keys]`;
  - m12 (drop the casefold) fails `[roots10-True]`;
  - m13 (drop normpath) fails `[roots8-True]`;
  - m15 (empty broad_only) fails `[roots4-False]`;
  - m6 (drop the accept guard) fails `[decline-content2]`;
  - m9 (drop the dry-run filter) fails `test_scan_dry_run_counts_no_server_surface_vector`;
  - m16 (drop the nothing-measured gate) fails `test_an_unmeasured_run_never_reads_as_passed`;
  - m17 (trust fixed at 1.0) fails the trust parametrisation.
- closed: [high] late elicitation reply logged in full (CWE-532) at 006161d
- closed: [medium] off-schema accept stored through the ValidationError text (CWE-312) at 006161d
- closed: [medium] roots false passed (credential descendants, `..`, case, `//`) at 006161d
- closed: [medium] guide gave no cleanup of widened roots at 006161d
- closed: [low] decline or cancel with content untested at 006161d (now pinned as passed, by design)
- closed: [low] dry-run exclusion untested at 006161d
- Confidence high: every claim was run end to end through the shipped CLI over stdio, and each has a known-positive or known-negative control.

## Residual risk
No `notifications/cancelled` is sent on timeout (a documented limit), so the host's form can stay open after the server has stopped waiting. Roots scoring still trusts `$HOME`, and Windows hosts are unmeasured.
