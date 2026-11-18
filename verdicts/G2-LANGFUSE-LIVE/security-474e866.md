Verdict: PASS
Gate: security
Item: G2-LANGFUSE-LIVE
PR: taoq-ai/ziran#503
Head: 474e866caa2fe7e630f4a011e06e163c36dcce7e
Confidence: high

## Findings
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:249 blocks: no. save_cursor still writes `langfuse-<hex>.tmp` through a planted symlink (CWE-59). This needs attacker-controlled files in the working directory and knowledge of sha256(host, public key). It is the same pattern as checkpoint.py and scan_cache.py, and the PR lists it as a known limit.
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:195 blocks: no. The cursor still has no upper limit: one observation with a future startTime moves it ahead, and later --incremental runs exit 0 with no findings. The gitignore half of this note is closed. Known limit.
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:172 blocks: no. A server that sends a new cursor on every page still paginates without bound; the probe stopped at 300 pages. A repeated cursor now stops the pull. Known limit.
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:167 blocks: no. An http:// LANGFUSE_HOST still sends basic auth in cleartext with no warning (CWE-319). Known limit.
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:231 blocks: no. `Retry-After: nan` still fails the run on 3.13 and later. The 60 s cap is still untested. Known limit.
- [low] ziran/infrastructure/trace_ingestors/langfuse_ingestor.py:151 blocks: no. A non-string `last_start_time` in the cursor still exits 2 without the "delete it" hint. Known limit.

## Probes
closed: [medium] langfuse_ingestor.py:270 RecursionError on a nested JSON-string input aborts the pull and wedges --incremental, at 474e866. It now catches `(ValueError, RecursionError)`.
Delta f8ae469..474e866: 7 files, +60/-3. The ingestor gains 13 lines: the RecursionError catch, a refusal of --incremental with --session-id, and a stop on a repeated meta.cursor. The rest is .gitignore (`.ziran/trace_cache/`), docs, spec and tests. The CLI and the analyzer are unchanged.
Fresh git archive of 474e866 with venvs on 3.11.15, 3.12.13, 3.13.14 and 3.14.7: the Langfuse tests give 37 passed on each.
Real-server CLI probes on all four Pythons. A 100000-level nested input now gives exit 1 (the critical chain is still found). Two --incremental runs in a row now give exit 1, then the cursor is saved, then exit 0. At f8ae469 both runs exited 2.
Key leakage, re-run on all four Pythons for -v text and json logs, 401, a 302 to another host, and connection refused: none of pk, sk or base64(pk:sk) appears in any output, and the second host gets no request.
Mutants in fresh copies. MA (restore `except ValueError`) is killed by test_deeply_nested_input_does_not_abort. MB (drop the repeated-cursor stop) makes test_repeated_cursor_exits_two hang past 60 s, so it is caught. MC (drop the --incremental with --session-id guard) is killed by test_incremental_with_session_refused.
Cursor guard spellings, as the request sequence and its outcome. A,B,A stops at request 3, and the same cursor twice stops at request 2. A dict or list cursor raises TypeError and exits 2, so it fails closed. 1 then "1" then 1 stops at request 3. An empty string ends the pull normally. Fresh cursors keep going: 301 requests until the probe stopped it.
The --incremental with --session-id guard raises ValueError before any request is sent.
Confidence is high because the blocker fix and every new guard were probed at this head on all four CI-relevant Pythons. The dependency-audit check was ignored as instructed (red on develop for an npm reason); pyproject.toml, uv.lock and the workflows are unchanged in this delta.

## Residual risk
The live Langfuse response shape is still not recorded. If the API returns `input` as structured JSON, a nested bomb would hit response.json() before this guard runs. That is the same gap file mode already has.
