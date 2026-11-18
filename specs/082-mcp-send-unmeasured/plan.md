# Implementation Plan: an MCP target that takes no chat prompt is unmeasured

**Branch**: `fix/082-mcp-send-unmeasured` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ eaf2ee5

## Summary

Drop `sampling/createMessage` from `MCPProtocolHandler.send` and log the no-chat case once. Make
the no-chat placeholder an error sentinel, so both executors count it as a prompt error. Mark a
vector no prompt measured with spec 071's `outcome: unmeasured`, and list it in the campaign's
`unmeasured` metadata so the existing INCOMPLETE labels and the `nothing_measured` gate apply.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: httpx, Pydantic v2, stdlib `logging`. No new dependencies.
**Storage**: none new. The scan cache already refuses results with `prompt_errors`.
**Testing**: pytest. Unit tests in `tests/unit/test_protocol_handlers.py` and
`tests/unit/application/test_attack_executor.py`; one integration test runs `AgentScanner` with a
real `HttpAgentAdapter` on an `httpx.MockTransport` MCP server, a `ScanCache`, and the report
generator.

## Constitution Check

- Hexagonal architecture: the application layer matches a sentinel string, as it does for the
  LangChain iteration-limit text; it imports nothing from infrastructure.
- Type safety: no new types; annotated code.
- Tests: test first; markers on every test.
- Simplicity: no new exception class, flag or option. The handler keeps returning a response, so
  the adapter's retry and breaker code is untouched.

## Code trace (develop @ eaf2ee5)

- `mcp_handler.py` `send`: loop over `completion/complete` and `sampling/createMessage`; on
  `ProtocolError` both, return the placeholder.
- `http_adapter.py` `_send_with_retry`: only `ProtocolError` trips `record_failure`; a normal
  return calls `record_success`.
- `attack_executor.py` `execute`: an error-sentinel reply `continue`s before the detectors, so
  `answered` stays 0 and `prompt_errors = len(prompt_attempts) - answered`.
- `tactics.py` `TacticExecutor.execute`: no sentinel check today; every reply is scored.
- `scan_cache.is_cacheable`: False when `prompt_errors` is set.
- `result_builder.ResultBuilder.build`: builds `metadata`; no `unmeasured` key for scans.
- Reports: `reports.py`, `html_report.py` and `main.py` print INCOMPLETE when
  `CampaignResult.unmeasured_vectors` is non-empty; `html_report._unmeasured` skips
  `outcome: unmeasured` results in the OWASP and ATLAS tables; `gate.py` fails on
  `nothing_measured` when every vector is unmeasured.

## Changes

1. `mcp_handler.py`: call `completion/complete` once; on `ProtocolError`, warn once per handler
   and return the placeholder.
2. `ziran/domain/replies.py` (new): `NO_CHAT_REPLY`, `ERROR_SENTINELS`, `is_no_chat_reply` (exact
   match) and `is_error_response`, moved out of `attack_executor.py` so the handler, both executors
   and the 400-line size guard all fit; `attack_executor.py` re-exports the old private names.
   When `answered == 0`, set `outcome: unmeasured` in the evidence.
3. `tactics.py`: a turn equal to the placeholder is a prompt error; with no evaluated turn and any
   prompt error, set `outcome: unmeasured`.
4. `result_builder.py`: `metadata[UNMEASURED_METADATA_KEY]` lists the unmeasured vector ids when
   there are any.
5. `phase.py`: docstring of `unmeasured_vectors` no longer says "empty for scans".
6. `docs/guides/remote-agents.md`: one line on MCP prompts.
