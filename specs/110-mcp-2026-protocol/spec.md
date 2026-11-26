# Feature Specification: the MCP client speaks the 2026-07-28 protocol and falls back to older versions

**Feature Branch**: `feat/109-mcp-2026-protocol`
**Created**: 2026-11-26
**Status**: Active

## The promise in our own words

`ziran scan --protocol mcp` talks to MCP servers with hand-rolled JSON-RPC in
`ziran/infrastructure/adapters/protocols/mcp_handler.py`. It never sends a protocol version
except in `initialize` (`2024-11-05`, used only by the health check and by protocol
auto-detection in `http_adapter.py`). MCP revision 2026-07-28 removes `initialize` and sessions:
every request carries its version, client info and client capabilities in
`params._meta` (`io.modelcontextprotocol/protocolVersion`, `.../clientInfo`,
`.../clientCapabilities`), mirrored in the `MCP-Protocol-Version` header, and a server that does
not support the version answers `UnsupportedProtocolVersionError` (code -32022, `data.supported`).
A server that speaks only 2026-07-28 rejects today's bare `tools/list`, so structured discovery
finds nothing and the scan has nothing real to attack.

After this change the handler works out the server's era once, before its first request, the way
the spec's Streamable HTTP binding says (basic/versioning, "Backward Compatibility"):

1. It sends `server/discover` with `2026-07-28` in `_meta` and the headers.
2. A `DiscoverResult` whose `supportedVersions` holds `2026-07-28` means a modern server: every
   later request carries the `_meta` fields and the `MCP-Protocol-Version`, `Mcp-Method` and (for
   `tools/call`, `prompts/get`, `resources/read`) `Mcp-Name` headers.
3. An `UnsupportedProtocolVersionError`, or a `DiscoverResult` without `2026-07-28`, means the
   server is modern but wants another version. If its list holds a legacy version ziran knows
   (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), ziran uses the newest one through
   `initialize`; otherwise the scan gets an error naming the server's versions.
4. Any other answer (a non-modern JSON-RPC error, an HTTP error without a modern error body, a
   result that is not a `DiscoverResult`, no answer) means a legacy server: ziran sends
   `initialize` with `2025-11-25`, keeps the version the server answers when ziran knows it,
   sends `notifications/initialized`, and then sends requests as it does today, plus the
   `Mcp-Session-Id` the server handed out and, from 2025-06-18 on, the `MCP-Protocol-Version`
   header. If `initialize` fails, ziran still sends today's bare requests, so a minimal JSON-RPC
   server scans as before.
5. A busy answer to the probe (an HTTP status in `retry.retry_on`, 429 and 5xx by default)
   leaves the era open and waits as the adapter's retries do (`Retry-After`, then exponential
   backoff), up to `retry.max_retries` times. A transport failure, a timeout or exhausted
   retries count as no answer: step 4, with one warning.
6. A HeaderMismatch (-32020) or MissingRequiredClientCapability (-32021) answer to the probe is a
   modern server rejecting ziran's request: every call fails with that code.

A result with `resultType: "input_required"` (MRTR, SEP-2322) is followed once: ziran records each
`elicitation/create` input request (mode, message, URL), flags a URL whose host differs from the
MCP server's host, declines every elicitation (`{"action": "decline"}`, a scanner never opens a
target's URL or fills its form) and retries the original request once with `inputResponses` and
the server's `requestState`. The records land in the response metadata
(`mcp_input_required`), and each URL with its flag is appended to the reply text, so the scan's
`agent_response` keeps it.

A scan that measured nothing already says so (spec 082): a prompt the server does not answer is a
prompt error, the vector is `unmeasured`, the reports read INCOMPLETE and `ziran ci` fails on
`nothing_measured`. Before this change a 2026-only server still discovered no tools, so its tool
chains were never analysed. Tests here pin the unmeasured outcome for a 2026 server without
`completion/complete` and for a server whose versions ziran does not know.

## Acceptance scenarios

1. Given an MCP server that only implements 2026-07-28, when a scan runs with `--protocol mcp`,
   then its tools are discovered and attacks are sent and answered instead of ending with nothing
   measured.
2. Given a 2024-11-05 server, when the same scan runs, then the client falls back to `initialize`
   and sends today's requests (no `_meta`), with the same discovered capabilities and replies.
3. Given a tool returning `resultType: "input_required"` with a URL elicitation, when the scan
   follows it, then the URL is recorded and flagged when its host differs from the server's host.
4. Given a 2025-11-25 Streamable HTTP server with sessions, when the scan runs, then ziran
   negotiates `2025-11-25` and sends the session id and version header on every request.
5. Given a modern server that supports only versions ziran does not know, when the scan runs,
   then it fails with an error that names the server's versions.
6. Given a 2026-only server that takes no chat prompt, or one whose versions ziran does not
   know, when the scan runs, then its vectors read unmeasured, never clean.

## Out of scope

- `x-mcp-header` parameter mirroring (`Mcp-Param-*`), `subscriptions/listen`, the tasks
  extension, caching by `ttlMs`, pagination of list results, and the deprecated HTTP+SSE
  transport.
- Routing attack prompts to MCP tools through `tools/call`: the scan still sends prompts through
  `completion/complete`, as today.
- New attack vectors for URL-mode elicitation phishing: left for a follow-up.

## Assumptions

- The 2026-07-28 changelog, versioning, transports, stdio and Streamable HTTP pages and
  `schema/2026-07-28/schema.ts` were read on 2026-11-26; error codes are the renumbered ones
  (UnsupportedProtocolVersion -32022, HeaderMismatch -32020, MissingRequiredClientCapability
  -32021). Overturned by a later erratum to that revision.
- The official `mcp` SDK in the lockfile (1.30.0) knows protocol versions up to 2025-11-25 only
  (`mcp/types.py` `LATEST_PROTOCOL_VERSION`), so the handler stays hand-rolled on httpx. Overturned
  when an SDK release with 2026-07-28 support is locked.
- "Host differs" compares the URL's host name with the configured server URL's host name; the
  port and scheme are not compared, and a URL with no host is flagged. Overturned if the owner
  wants an origin (scheme, host, port) comparison.
- The era is decided once per handler and not re-probed when a later request fails. Overturned if
  real servers switch era behind one URL.
- A legacy server answering `initialize` with a version ziran does not know is used without the
  version header, as today.
