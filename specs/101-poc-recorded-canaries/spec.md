# Feature Specification: Generated PoCs check for the canaries the scan recorded

**Feature Branch**: `fix/poc-recorded-canaries`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-POC-CANARY (goal G-b)

## The promise in our own words

Some agents leak a canary through a tool call and never repeat it in their reply text. The
scan records the call and its arguments, so the canary is in `evidence["tool_calls"]`. The
indicator detector only reads reply text, so `matched_indicators` holds labels such as
`llm_judge_verdict` and `http_post (sends data)`, and spec 100's `_indicators` drops both
(no reply holds them). So the cURL PoC has nothing to grep and exits 2, and the Python PoC
counts any reply with a tool call as reproduced and exits 0. That holds on the vulnerable
agent and on the fixed one alike, so neither PoC tells them apart.

After the fix:

- The success indicators start with the canaries the scan recorded: every token that holds
  `canary` (any case) and a digit, found in the recorded reply or in a recorded tool call's
  arguments (a JSON-string argument is decoded first). The matched indicators follow, kept
  when they occur in that reply or those arguments. With no recorded reply, every matched
  indicator stays, as in spec 100.
- Both PoCs match those indicators against the whole response body, tool-call arguments
  included: the cURL PoC greps the raw body, the Python PoC every string in the parsed JSON.
- The Python PoC no longer counts a reply with tool calls as reproduced. With no indicator it
  exits 2, as the cURL PoC does.
- A fixed agent restarted with a fresh canary does not match the recorded one, so it reads not
  reproduced.
- Spec 099's quoting, spec 100's request shapes and exit codes, and the adapter-driven Python
  script for scans without an HTTP target stay as they are.

## Acceptance scenarios

1. **Given** a scan of an OpenAI-protocol agent whose tool call carries the canary but whose
   reply text does not, **When** its cURL and Python PoCs run against that agent, **Then** both
   print reproduced and exit 0.
2. **Given** the same agent fixed (it still calls the tool, with a fresh canary), **When** both
   PoCs run, **Then** both print not reproduced and exit 1.

## Requirements

- FR-001: `_indicators(result)` returns the recorded canaries (tokens of `[A-Za-z0-9_-]` that
  contain `canary` case-insensitively and hold a digit, from `agent_response` or else
  `response_snippet`, and from each tool call's `arguments`, `input` or `args`), then the matched
  indicators found in that text, without duplicates.
- FR-002: A tool's name is not read for canaries; a bare word `canary` is not one.
- FR-003: The httpx Python PoC returns 0 on a match, 1 when indicators exist and none matches,
  2 with no indicator; tool calls in the reply do not change the result.
- FR-004: Spec 099 FR-001 to FR-007 and spec 100 FR-001, FR-003, FR-005 and FR-006 hold.

## Assumptions

- A canary names itself: a planted token holds the word `canary` and a digit (`ZX-CANARY-7731`,
  `CANARY3024`). The scan records no other mark of which argument value is the canary, and
  taking every argument value would match a fixed agent that calls the same tool with the same
  URL. Overturned if scans plant canaries in another form; then the target config or the vector
  would name the canary.
- The cURL PoC greps the raw JSON body. A canary is `[A-Za-z0-9_-]` only, so JSON escaping of
  the arguments string does not split it.
- Dropping the Python PoC's tool-call fallback changes a documented exit code (0 to 2) for a
  finding with no indicator. The exit codes are not a declared API (spec 100), and the old
  result reported a fixed agent as vulnerable. So this is a `fix:` with a release note.
- The adapter-driven script still reports tool calls as reproduced: the brief keeps it as is.
  Overturned if it should follow the HTTP script; that is a separate item.
