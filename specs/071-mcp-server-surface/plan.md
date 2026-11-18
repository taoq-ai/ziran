# Implementation Plan: the MCP server-initiated attack surface

**Branch**: `feat/071-mcp-server-surface` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). New optional extra `mcp` (`mcp>=1.30,<2`, the range
the uv override already pins, so the lock keeps mcp 1.30.0). Pydantic v2, stdlib `asyncio`,
`json`, `urllib.parse`, `pathlib`, Click. mypy runs without extras in CI, so `mcp.*` joins the
`ignore_missing_imports` list and the server registers its tool with `add_tool`, not a decorator.

## Design

1. Domain, `ziran/domain/entities/mcp_server_surface.py`: `McpServerRequest` (method, sampling
   `system_prompt`/`include_context`/`max_tokens`, elicitation `fields`/`sensitive_fields`,
   roots `denied_roots`, per-method validation) and `McpServerReply` (vector ID, method,
   `status` reply/error/timeout, `result`, `error`, client name and capabilities).
   `AttackVector` gains `mcp_server_request: McpServerRequest | None` and a validator for FR-004.
2. Library: `_parse_vector` reads `mcp_server_request`; `get_attacks_for_phase` drops vectors
   that have one.
3. Application, `ziran/application/mcp_server_surface/scoring.py`: `score_reply(vector, reply,
   home)` returns an `AttackResult`; `build_campaign_result(vectors, replies)` returns the
   `CampaignResult` (a missing reply is unmeasured, "the client never called the tool").
4. Infrastructure, `ziran/infrastructure/mcp_hostile/server.py`: `build_server(vectors,
   record_dir, timeout)` returns a FastMCP server whose `lookup_glossary` tool sends each
   vector's request through `ctx.session` (`create_message`, `elicit_form`, `list_roots`) inside
   `asyncio.wait_for`, turns the reply into an `McpServerReply` (elicitation values reduced to
   present and length), and writes the record and the `CampaignResult` after each call.
5. CLI, `ziran/interfaces/cli/mcp_hostile_server.py`: `ziran mcp-hostile-server` with
   `--vector` (repeatable), `--family` (repeatable), `--record-dir`, `--timeout`. It runs
   `server.run("stdio")` and writes the results again on exit. Registered in `main.py`; the
   scan dry-run count skips server-surface vectors.
6. Vectors: `mcp_server_surface.yaml`, eight critical vectors with `protocol_filter: [mcp]`, a
   sub-family tag and OWASP/ATLAS mappings.
7. Docs: `docs/guides/mcp-hostile-server.md` and its `mkdocs.yml` entry; `generate_all.py`
   regenerates the coverage docs; `regression_check.py --update-baseline` refreshes the baseline.

## Tests

Unit: the domain validation, the library exclusion over every phase and coverage level, and
scoring of naive, careful and unsupported replies. Integration: the server over the SDK's
in-memory transport with naive, careful and `Method not found` clients; the CLI over stdio with
a `ClientSession`, then `ziran report` on the written JSON.

## Constitution check

Hexagonal layers kept: domain models, application scoring, infrastructure server, CLI driver.
Typed (mypy strict), async I/O, vectors in YAML, Pydantic models, one optional dependency
already in the lock, tests first.
