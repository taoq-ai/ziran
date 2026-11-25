# Feature Specification: PoCs reproduce against OpenAI-protocol and custom-path HTTP targets

**Feature Branch**: `fix/poc-target-protocol`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-POC-PROTOCOL (goal G-b)

## The promise in our own words

The cURL PoC always posts `{"message": prompt}` to one endpoint (`http://localhost:8000/invoke`
unless the caller passes one) and greps the reply for every string in `matched_indicators`.
Against an OpenAI-compatible target the scan spoke `POST {url}/v1/chat/completions` with a
`messages` body, and against a REST target it used the configured path, method, message field
and extra body. So the PoC sends a request the target does not understand, and it prints
"Not reproduced" for a finding that does reproduce. `matched_indicators` can also hold labels
no reply contains (`llm_judge_verdict`, a tool name and its description). The Python PoC only
prints usage: it needs a ZIRAN adapter to run at all.

After the fix:

- The generator takes the scan's `TargetConfig`. For `openai` it builds the request the
  OpenAI handler sends: `POST {url}/v1/chat/completions` with `model`, one user message, and
  `temperature` / `max_tokens` when set. For `rest` it builds the REST handler's request: the
  configured method, `{url}/{request_path}`, `{message_field: prompt, **extra_body}`. Every other
  protocol, and no target, keeps today's form: `POST {"message": prompt}`, to the target URL when
  there is one.
- The success check uses only the matched indicators that occur in the agent reply the scan
  recorded (the canary or the matched text). With no recorded reply, every matched indicator
  stays.
- The cURL PoC keeps spec 099's quoting and writes. It exits 0 when an indicator is in the
  reply, 1 when none is, and 2 when the finding has no text indicator to check.
- For an `openai` or `rest` target the Python PoC is a standalone script needing only httpx
  (it imports `json`, `sys` and `httpx`). It sends the same request, checks every string in
  the JSON reply, and exits 0, 1 or 2 the same way. With no text indicator it reports a reply
  that holds tool calls as reproduced, as the old adapter check did; a recorded indicator
  decides first.
- With no target (framework and in-process scans) or another protocol (MCP, A2A, browser,
  unresolved `auto`), the Python PoC stays the adapter-driven script: `reproduce(adapter)`,
  the configured imports and the configured run instructions, as before.
- `ziran scan --target` writes a cURL PoC next to the Python one for `openai` and `rest`
  targets only, built from the target config with the protocol the adapter detected when the
  config says `auto`. `ziran poc --target <yaml> [--protocol <p>]` builds the PoCs from a
  target config; `--protocol` overrides its protocol, as in `scan`. `poc` cannot resolve
  `auto`, so an `auto` config falls back unless `--protocol` is given.

## Acceptance scenarios

1. **Given** a scan of an OpenAI-protocol agent that leaks a canary, **When** its cURL PoC runs
   against that agent, **Then** it prints the reply with the canary, reports the finding as
   reproduced and exits 0.
2. **Given** the same agent fixed, **When** the PoC runs, **Then** it reports not reproduced and
   exits non-zero.
3. **Given** a prompt holding a single quote, `$()` and backticks, **When** the cURL PoC is
   generated and run, **Then** no shell command runs and the agent receives the prompt byte for
   byte.
4. **Given** a REST target with a custom path, method, message field and extra body, **When** its
   cURL and Python PoCs run against a stub of that target, **Then** the stub receives that path
   and body, and the exit codes follow scenarios 1 and 2.
5. **Given** the Python PoC for scenario 1, **When** it runs with httpx installed and no ZIRAN
   import, **Then** it exits 0 against the leaking agent and 1 against the fixed one.

## Requirements

- FR-001: `PoCGenerator(output_dir, config=None, target=None)`; the request it builds for
  `openai` and `rest` equals the request the matching protocol handler sends for one prompt.
- FR-002: The success indicators are the matched indicators found (case-insensitive) in
  `agent_response`, else in `response_snippet`; with neither recorded, all matched indicators.
- FR-003: The cURL PoC keeps spec 099 FR-001 to FR-007 (quoting, `--url`, `grep -qiF`, atomic
  writes); the body is `json.dumps` of the built body, the method a quoted `-X` word.
- FR-004: Both PoCs exit 0 reproduced, 1 not reproduced, 2 no text indicator (Python: unless a
  reply holds tool calls).
- FR-005: The httpx Python PoC imports `json`, `sys` and `httpx` once each; the adapter
  Python PoC is the base script for no target and for non-HTTP protocols.
- FR-006: `generate_all` adds the cURL PoC for an `openai` or `rest` target; `scan --target`
  passes its config with the resolved protocol; `poc --target` loads one and `poc --protocol`
  overrides its protocol.

## Assumptions

- The PoC exit codes are not a declared API: `docs/reference/cli.md` documents none, and the
  item's acceptance asks for exit 0 on a reproduced finding. So this is a `fix:` with a release
  note, not a major. Overturned if a release note or doc promised the old codes.
- A PoC sends the successful prompt as a single turn. The OpenAI handler keeps a multi-turn
  history, so a finding that needs earlier turns may not reproduce. Overturned if multi-turn
  findings turn out common; then the PoC would replay the conversation.
- Auth and custom headers stay out of the scripts: a target's token is a secret and must not be
  written to disk. A user adds `-H` to the curl line, or headers to `httpx.request`.
- The cURL check greps the raw reply. An indicator with a `"`, `\` or non-ASCII character is
  JSON-escaped in the reply and can miss; canaries are plain text. The Python PoC decodes the
  JSON and has no such gap.
- The request shape is copied from the two handlers, not imported: the application layer must
  not import infrastructure. A contract test sends one prompt through each real handler and
  compares the request.
- Framework scans have no target, and the base shipped their Python PoC as
  `reproduce(adapter)` with a LangChain example in its usage text. That form stays for no
  target and for MCP, A2A, browser and unresolved `auto`. The httpx script is written only
  where it can send the scan's request (`openai`, `rest`), so no existing PoC loses its entry
  point and the change is not breaking. Overturned if an adapter user relied on the adapter
  script for an `openai` or `rest` target; `ziran poc` without `--target` still writes it.
- The cURL PoC is skipped in `generate_all` outside `openai` and `rest`, rather than labelled:
  it cannot reproduce there, and skipping is the smaller change. `--format curl` still writes
  one on request, in today's form.
