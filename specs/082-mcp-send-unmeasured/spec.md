# Feature Specification: an MCP target that takes no chat prompt is unmeasured, never resisted

**Feature Branch**: `fix/082-mcp-send-unmeasured`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: G5-MCP-SEND-UNMEASURED (goal G-5), the follow-up recorded in G2-MCP-SURFACE's promise
and PR #505.
**Base**: `develop` @ eaf2ee5.

## The promise in our own words

Today `MCPProtocolHandler.send`, given no `tool_name`, posts `completion/complete` and then
`sampling/createMessage` with a chat `messages` body. A spec-compliant MCP server rejects both:
`sampling/createMessage` is a request a server sends to its client, never the other way. `send`
then returns the placeholder `[MCP server does not support direct messaging ...]` as content.
`AttackExecutor` scores that placeholder through the detector pipeline as a real reply, so the
vector reads as resisted with no `prompt_errors`, and the spec-049 scan cache keeps it as clean.
A scan of such a server reports PASSED although no prompt reached it.

After this change:

1. `send` never posts `sampling/createMessage`. It tries `completion/complete` alone.
2. When `completion/complete` fails, the placeholder is an error sentinel. The prompt never
   reaches the detectors and counts as a prompt error, so the result carries `prompt_errors` and
   the scan cache does not store it. This holds for single-turn and multi-turn vectors.
3. The handler logs one warning per scan that the target takes no chat prompt, not one per
   prompt. `send` returns normally, so the adapter's retry loop and circuit breaker never see it.
4. A vector no reply measured carries `evidence["outcome"] = "unmeasured"` and its id goes into
   `CampaignResult.metadata["unmeasured"]` (spec 071's `UNMEASURED_METADATA_KEY`). The reports
   then read INCOMPLETE instead of PASSED, and `ziran ci` fails on `nothing_measured` when no
   vector was measured.
5. A server that answers `completion/complete` keeps today's path: its text is the content.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A no-chat MCP server is never reported as resisting (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a fake MCP server that answers `tools/list` and returns a JSON-RPC error for
   `completion/complete`, **When** `send` runs a prompt with no `tool_name`, **Then** the only
   chat method it called is `completion/complete`, never `sampling/createMessage`.
2. **Given** an HTTP MCP target like that, **When** `AttackExecutor` runs a one-prompt vector,
   **Then** the detector pipeline is not called, the result's evidence has `prompt_errors` 1, and
   `is_cacheable` returns False.
3. **Given** 10 vectors against that target, **When** the scan runs, **Then** the circuit breaker
   stays closed, the no-chat warning is logged once, the scan cache holds no entry, and the
   markdown and HTML reports read INCOMPLETE, never PASSED.
4. **Given** a multi-turn vector against that target, **When** it runs, **Then** no turn reaches
   the detectors and the result is unmeasured with `prompt_errors`.

### User Story 2 - A chat-capable MCP server keeps working (Priority: P1)

1. **Given** a server that answers `completion/complete` with text (the case in
   `tests/unit/test_protocol_handlers.py::TestMCPHandler::test_send`), **When** `send` runs,
   **Then** the text comes back as content, as today.

### Edge Cases

- A transport failure on `completion/complete` (HTTP 5xx, connection reset) also yields the
  placeholder, as today. That prompt counts as an error and stays out of the cache, which is the
  safe side. The warning names the underlying error.
- A target whose reply quotes the placeholder inside other text is still scored: only a reply that
  equals the placeholder (after strip) is an error, so a target cannot hide a finding by quoting it.
  A reply that is exactly the placeholder carries no evidence and reads unmeasured.

## Requirements *(mandatory)*

- **FR-001**: `MCPProtocolHandler.send` MUST NOT send `sampling/createMessage`.
- **FR-002**: `is_error_response` (in `ziran/domain/replies.py`, shared by the handler and both
  executors) MUST match the MCP no-chat placeholder by exact equality after strip, never as a
  substring. The LangChain phrases keep their substring match in the single-turn executor.
- **FR-003**: `TacticExecutor` MUST skip a turn equal to the placeholder as a prompt error. It
  adds no check for the other sentinels, which keep their develop behaviour there.
- **FR-004**: A result no reply measured MUST carry `evidence["outcome"] == "unmeasured"`, and
  `ResultBuilder` MUST list it under `UNMEASURED_METADATA_KEY`.
- **FR-005**: The no-chat warning MUST be logged at most once per handler.

## Assumptions

- The brief from the lead asks that the result is never reported as passed and that tests reach
  the rendered report. The item lists "showing unmeasured vectors in reports" as outside. We
  reuse the labels spec 071 already renders (INCOMPLETE, `nothing_measured`) and add no report
  code. The per-attack HTML card still says "Blocked"; changing it is a report change, so it is a
  candidate for its own item. Overturned if the owner wants the card in this PR.
- "Unmeasured" in a scan means no prompt of the vector reached the detectors, for any reason
  (no-chat, timeout, connection error, iteration-limit sentinel). A vector where some prompts
  reached the detectors stays measured. This also changes scans of other targets where every
  prompt failed: they now read INCOMPLETE, which is the honest result. Overturned if a gate shows a
  caller that relies on such a scan reading PASSED.
- The multi-turn path (`tactics.py`) is in scope: the promise covers every vector that no prompt
  reached, and it is three lines.
- `completion/complete` keeps its current `messages` body (promise point 3), although the MCP
  spec defines `ref` and `argument` params for it.

## How this fails

1. A target forges the placeholder to hide a finding. Bounded by the exact match: only a reply
   that is the placeholder and nothing else is dropped, and its vector reads unmeasured.
2. A transient error on the first prompt prints the no-chat warning for a server that does chat.
   The warning names the method, host and error class (never the URL's userinfo or query, or the
   server's text), and each later prompt still tries `completion/complete`.
3. Unmeasured vectors still count toward the phase trust score and resilience metrics as not
   vulnerable. The overall verdict says INCOMPLETE; the numbers are a known residual.

## Success Criteria

- **SC-001**: the scenarios above pass as tests in `tests/unit/test_protocol_handlers.py`,
  `tests/unit/application/test_attack_executor.py` and `tests/integration/test_mcp_no_chat_scan.py`.
- **SC-002**: `ruff check`, `ruff format --check` and `mypy ziran/` pass.
