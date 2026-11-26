# Implementation Plan: the MCP client speaks the 2026-07-28 protocol

**Branch**: `feat/109-mcp-2026-protocol` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), httpx (existing), stdlib `base64`/`json`/`asyncio`/
`urllib.parse`. No new dependencies. The `mcp` SDK in `uv.lock` (1.30.0) stops at 2025-11-25, so
it is not used.

## Constitution check

- Hexagonal: the change stays in the MCP adapter (`infrastructure/adapters/protocols/`) and the
  auto-detection probe in `http_adapter.py`. Nothing under `application/` changes, so the
  `agent_scanner` size budgets are untouched.
- Types: mypy strict; JSON-RPC payloads stay `dict[str, Any]` as in the other protocol handlers.
- Tests: in-process fake servers on `httpx.MockTransport`, one per version shape.
- Simplicity: no new module and no new exception type; negotiation reads the raw JSON-RPC
  message from one `_exchange` helper.

## Design

`MCPProtocolHandler`:

- `_negotiate()`: under an `asyncio.Lock`, once per handler. Sends `server/discover` with the
  modern `_meta` and headers, then decides modern, legacy with a version from the server's list,
  or legacy by fallback (spec steps 1 to 6). Legacy runs `initialize` and
  `notifications/initialized`. Sets `_era`, `_version` (header value or `None`), `_reachable`.
- `_exchange(method, params, version)`: one HTTP POST. Adds `Accept`, `Mcp-Method`,
  `Mcp-Name` (Base64 sentinel when not plain ASCII), `MCP-Protocol-Version` and
  `Mcp-Session-Id` when known. Parses a JSON body or a `text/event-stream` body (the `data:` line whose `id` matches) and returns the
  response with the message, or `None` when it is unreadable or nests too deep.
- `_jsonrpc_call(method, params)`: negotiates, adds `_meta` for a modern server, posts, and
  raises `ProtocolError` on an HTTP error (keeping the status for the retry logic), an
  unreadable body or a JSON-RPC error, as today.
- `_follow(method, params)`: `_jsonrpc_call`, then for `input_required` records the elicitations,
  declines them and retries once.
- `health_check()`: negotiates and returns whether discover or initialize answered.

`HttpAgentAdapter._probe_mcp` uses `MCPProtocolHandler.health_check()`, so auto-detection finds a
modern server too.

## Test plan

`tests/mcp_servers.py` holds the fakes (modern-only, 2025-11-25 with sessions, 2024-11-05).
`tests/unit/test_mcp_versions.py` adds a dual-era server and covers negotiation, request shape,
discovery, `tools/call`, `completion/complete`, `input_required` with a same-host and a foreign-host URL, unknown-versions error, SSE body,
deep-nested body and auto-detection.
`tests/integration/test_mcp_versions_scan.py`: `AgentScanner` runs against the 2026-only and
2024-11-05 fakes, a 2026 fake with no chat method and one with unknown versions only.
