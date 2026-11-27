# Spec 137: scan targets carry a stable name

Status: Active. Follows spec 135 (scan AI-BOM).

## Promise (in my words)

A scan target config may carry a `name`. An MCP target without one falls back to the server's
`initialize` `serverInfo.name`, else `host:port`. The scan BOM uses that name for the `mcp:` ref,
the service name and the `agent:` ref, so `analyze-traces --aibom` matches `mcp__<name>__<tool>`
and the agent's service name instead of flagging the scanned target as shadow.

## Acceptance

- An MCP target whose `serverInfo.name` is `search`, and a trace naming `mcp__search__x`: `search`
  is not shadow.
- Two MCP targets on one host with different ports get distinct refs.
- The config `name` wins over `serverInfo.name`.
- A `name` outside 1-64 characters of letters, digits, `.`, `_`, `-` (first alphanumeric) is a
  config error; no `:`, `@`, `/`, `?` or `=` can pass, so a URL with credentials cannot.

## Design

- `TargetConfig.name` with `TARGET_NAME` (domain). The MCP handler keeps `serverInfo.name` from
  `initialize` (and a `server/discover` result) only if it fullmatches `TARGET_NAME`; the server's
  text is untrusted. `HttpAdapter.server_name` exposes it; the CLI passes it to `build_scan_aibom`.
- Precedence: config `name`, A2A card name, MCP `serverInfo.name`, `host[:port]`, source stem.
  The port is part of the name only when the URL states one.

## Assumptions

- The modern `server/discover` result may also carry `serverInfo`; read if present, else the name
  stays unset and `host:port` is used. Overturned if the 2026 binding names another key.
- A name check by character set is enough for "no secrets"; a bare token that fits the set is the
  operator's to avoid.
