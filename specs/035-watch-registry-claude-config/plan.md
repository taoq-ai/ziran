# Implementation Plan: watch-registry imports MCP servers from Claude Code configuration

**Branch**: `035-watch-registry-claude-config` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #422 — independent of #417 / #421 (no shared code), can merge in any order.

## Summary
Add `ziran watch-registry --from-claude-config PATH`. A new infrastructure loader turns a Claude
Code MCP config (project `.mcp.json`, plugin `.mcp.json`, user settings `mcpServers`) into
`ServerEntry` objects; `ServerEntry` gains `command`/`args` (plus `SecretStr` `env`/`headers` that
never serialise); the CLI fetcher gains a stdio path (asyncio subprocess, newline JSON-RPC,
`initialize` + `tools/list`, timeout, kill on exit). `watch()` runs `MCPMetadataAnalyzer` on first
registration and returns the servers it could not fetch so the CLI can exit `2` for "could not
run", distinct from `1` for high/critical findings.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: pydantic v2 (`SecretStr`, `model_validator`), click, httpx, stdlib
`asyncio` subprocess / `json` / `re` / `os`. **No new runtime dependencies.** Tests: pytest
(asyncio_mode=auto), `respx` (already a dev dependency) for the HTTP fake.
**Storage**: unchanged — `JsonFileStore` snapshots under `--snapshot-dir` (`.ziran/snapshots/`).
**Testing**: pytest unit + integration; in-repo stdio fixture server run with `sys.executable`;
no network, no LLM.
**Project Type**: CLI / library.
**Constraints**: secrets from `env`/`headers` never persisted or logged; stdio fetch bounded by a
timeout (default 30 s, parity with the HTTP client's `timeout=30.0`).

## Constitution Check
| Principle | Status | How |
|---|---|---|
| I. Hexagonal | PASS | `ServerEntry` (domain) only gains fields + validator. Metadata analysis is wired in `application/registry_watch/watcher_service.py`, importing another application module (`application/static_analysis`). The Claude config parser is an infrastructure adapter (`infrastructure/config/claude_mcp_config.py`), next to the existing `env_yaml.py`. The stdio transport lives with the existing HTTP fetcher in the CLI driving adapter (`interfaces/cli/watch_registry.py`), where it is today; no inward dependency is reversed. |
| II. Type safety | PASS | All new functions annotated; pydantic for `ServerEntry`; mypy strict on `ziran/`. `url: str | None` is narrowed before use. |
| III. Test coverage | PASS | Unit tests for loader and `watch()` changes; integration tests (marked) for stdio fetcher, CLI acceptance, secret leak and exit codes. Test-first per tasks.md. |
| IV. Async-first | PASS | Stdio fetch uses `asyncio.create_subprocess_exec`; HTTP stays on httpx. Config file read stays synchronous at the CLI entry point, as `--config` does today (allowed: sync at CLI entry). |
| V. Extensibility | PASS | Reuses the `ManifestFetcher` protocol and `SnapshotStore` port; no new ports. |
| VI. Simplicity | PASS | No `mcp` SDK dependency: ~40 lines of stdlib JSON-RPC over stdio, only `initialize` + `tools/list`. No new CLI flags beyond the one required (timeout is a constructor arg, not a flag). One new source module. |
| Quality gates | PASS (to verify at implement) | ruff, ruff format, mypy strict, pytest `--cov` >= 85%. |

## Design (exact changes)

### 1. `ziran/domain/entities/registry.py`
- `ServerEntry`:
  - `url: str | None = None` (was required `str`).
  - `command: str | None = None`, `args: list[str] = Field(default_factory=list)`.
  - `env: dict[str, SecretStr] = Field(default_factory=dict, exclude=True, repr=False)` and
    `headers: dict[str, SecretStr] = Field(default_factory=dict, exclude=True, repr=False)`.
    `exclude=True` keeps them out of `model_dump`/`model_dump_json`; `SecretStr` masks `str`/`repr`.
  - `@model_validator(mode="after")` `_require_endpoint`: raise `ValueError("server requires 'url'
    or 'command'")` when both are `None`. Existing YAML entries (`name`, `url`, `transport`) validate
    unchanged.
- `DriftFinding.drift_type` comment: add `tool_poisoning`.

### 2. `ziran/application/registry_watch/watcher_service.py`
- New helper `_metadata_findings(server_name: str, tools: list[dict[str, Any]]) -> list[DriftFinding]`:
  runs a module-level `MCPMetadataAnalyzer()` (stateless) via `analyze_capabilities(tools)` on the
  raw `tools/list` dicts (it already reads `name` + `description` + `inputSchema.properties`) and maps
  each `MCPMetadataFinding` to `DriftFinding(server_name, drift_type="tool_poisoning",
  severity=f.severity, tool_name=f.tool_id, field=f.field, current_value=f.snippet,
  message=f"Suspicious tool metadata ({f.pattern_matched}) on server '{server_name}': {f.recommendation}")`.
- `watch()`:
  - Return type becomes `tuple[list[DriftFinding], list[str]]` — `(findings, unreachable_server_names)`.
    Update docstring.
  - In the fetch `except Exception as exc` branch: append `server.name` to `unreachable`, log
    `manifest_fetch_failed` with `server=server.name, error=type(exc).__name__` only (never
    `str(exc)`: exception text may carry URLs, args or payloads). Snapshot untouched (unchanged).
  - When `old_snapshot is None` (first registration): `all_findings.extend(_metadata_findings(server.name, raw.get("tools", [])))`.
    When a baseline exists: diff only (unchanged).
- `emit_findings` unchanged.

### 3. `ziran/infrastructure/config/claude_mcp_config.py` (new)
- `class ClaudeConfigError(ValueError)` — messages name the file, server key and field only.
- `load_claude_mcp_config(path: Path) -> list[ServerEntry]`:
  1. `json.loads(path.read_text(encoding="utf-8"))`; `JSONDecodeError` / non-object → `ClaudeConfigError`.
  2. Server map = `data["mcpServers"]` if present, else `data` itself (plugin flat form). Must be a
     non-empty object whose values are all objects, else `ClaudeConfigError("no mcpServers in <path>")`.
  3. Per entry: expand placeholders in `command`, each `args` item, `url`, and `env`/`headers`
     values with `_expand(value, env_map)` where `env_map = {"CLAUDE_PLUGIN_ROOT": str(path.parent.resolve()), **os.environ}`
     and `_expand` is one `re.sub` over `\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}` returning the
     variable, else the default, else the placeholder unchanged.
  4. Transport: `command` present and `type` in (absent, `"stdio"`) → `"stdio"`; `url` present and
     `type` in (absent, `"http"`) → `"streamable-http"`; `type == "sse"` → `"sse"`; anything else →
     `ClaudeConfigError(f"{path}: server '{name}': unsupported type")` (do not echo the value).
  5. Build `ServerEntry(name=key, url=..., transport=..., command=..., args=..., env=..., headers=...)`;
     catch `ValidationError` and re-raise `ClaudeConfigError` built from
     `exc.errors(include_input=False, include_url=False)` (`loc` + `msg` only — pydantic's default
     `str(exc)` includes input values and would leak secrets).
  6. Log once per server via `get_logger(__name__)`: event `claude_mcp_server_loaded` with
     `server`, `transport`, `env_keys=sorted(env)`, `header_keys=sorted(headers)` — key names only.
- Placeholder with no value and no default stays literal (spec edge case); no exception.

### 4. `ziran/interfaces/cli/watch_registry.py`
- Rename `HttpManifestFetcher` → `MCPManifestFetcher` (only referenced in this module) with
  `__init__(self, timeout: float = 30.0)`.
  - `fetch(server)`: `if server.command is not None: return await self._fetch_stdio(server)`;
    otherwise the existing HTTP body, with `url` narrowed (`if server.url is None: raise ValueError`)
    and `httpx.AsyncClient(timeout=self._timeout, headers={k: v.get_secret_value() for k, v in server.headers.items()})`.
  - `_fetch_stdio(server)`:
    `proc = await asyncio.create_subprocess_exec(server.command, *server.args, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, env={**os.environ, **{k: v.get_secret_value() for k, v in server.env.items()}}, limit=16 * 1024 * 1024)`
    (large `limit`: a `tools/list` line routinely exceeds the 64 KiB default; `stderr=DEVNULL` so
    server diagnostics never reach ZIRAN's output). Then
    `try: return await asyncio.wait_for(self._stdio_session(proc), self._timeout)` /
    `finally: if proc.returncode is None: proc.kill(); await proc.wait()`.
  - `_stdio_session(proc)`: `await _rpc(proc, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ziran", "version": __version__}})`;
    write `{"jsonrpc": "2.0", "method": "notifications/initialized"}`; `result = await _rpc(proc, 2, "tools/list", {})`;
    return `{"tools": result.get("tools", []), "resources": [], "prompts": []}`.
  - `_rpc(proc, id, method, params)`: write one JSON line + `drain()`; `readline()` until a JSON
    object with `id == id` (skip blank, non-JSON, and notification lines); EOF →
    `ConnectionError(f"{method}: server closed stdout")`; `"error"` in response →
    `RuntimeError(f"{method} returned a JSON-RPC error")` (no payload echo).
  - Pagination (`nextCursor`) is ignored, as in the HTTP fetcher.
- `watch_registry` command:
  - `--config` loses `required=True`. New `--from-claude-config` (`claude_config_path`,
    `click.Path(exists=True, dir_okay=False, path_type=Path)`; a missing file is Click's own exit 2).
  - `if (config_path is None) == (claude_config_path is None): raise click.UsageError("pass exactly one of --config or --from-claude-config")` (exit 2).
  - Config loading wrapped: `--from-claude-config` → `RegistryConfig(servers=load_claude_mcp_config(path))`
    catching `(OSError, ClaudeConfigError)`; `--config` → existing `load_yaml_with_env` +
    `RegistryConfig.model_validate` catching `(OSError, yaml.YAMLError, EnvVarError, ValidationError)`.
    On error print `Error: could not read config <path>: <safe detail>` to stderr and
    `raise SystemExit(2)`. Safe detail: `str(exc)` for `ClaudeConfigError`/`EnvVarError`/`OSError`;
    `loc: msg` pairs from `errors(include_input=False)` for `ValidationError`; the exception type
    name only for `yaml.YAMLError` (its text quotes the offending line).
  - `findings, unreachable = asyncio.run(watch(registry_config, store, MCPManifestFetcher()))`.
    Report writing unchanged. If `unreachable`: print `Could not reach server(s): <names>` (names
    only) to stderr.
  - Exit: `if delivery_failed or unreachable: raise SystemExit(2)`, then the existing
    high/critical gate `→ SystemExit(1)`. Update the exit-code comment.
  - Command docstring (Click help) gains a `\b` exit-code block: `0` clean, `1` high/critical
    finding, `2` could not run (usage, config, unreachable server, alert delivery).

### 5. Tests
- `tests/fixtures/mcp_stdio_server.py` (new, not collected: no `test_` prefix). Stdlib only.
  `argv[1]` = path to a JSON file with the tool list, re-read on every `tools/list` (so a test can
  change a description between runs); optional `argv[2]` = name of an env var that must be set or
  the process exits 1 (proves `env` is passed). Reads stdin lines; answers `initialize` with
  `{"protocolVersion", "capabilities": {"tools": {}}, "serverInfo"}`; ignores messages without
  `id`; answers `tools/list`; `-32601` for other methods. Never prints its environment.
- `tests/unit/test_claude_mcp_config.py` (new).
- `tests/unit/test_registry_watcher.py` (extend; adapt the three existing `watch()` call sites to
  the tuple).
- `tests/integration/test_watch_registry_cli.py` (extend): stdio fetcher, acceptance, secret
  leak, exit codes. The existing `test_cli_handles_unreachable_server` changes its expected exit
  code `0 → 2` (spec A2) and keeps asserting the report is written.

### 6. Docs
- `docs/reference/cli.md`: new `### ziran watch-registry` section (after `ziran audit`): options
  table incl. `--from-claude-config`; accepted input shapes (project/plugin `.mcp.json`, user
  settings `mcpServers`; stdio `command`/`args`/`env`, HTTP/SSE `url`/`type`/`headers`); placeholder
  expansion; secret rule ("values of `env`/`headers` are used only to connect; only key names are
  logged"); first-registration `tool_poisoning`; exit-code table (`0`/`1`/`2`, precedence
  `2 > 1 > 0`); example `ziran watch-registry --from-claude-config .mcp.json --snapshot-dir .ziran/snapshots --out reports --format json`
  and the JSON report shape (list of `DriftFinding`: `server_name`, `drift_type`, `severity`,
  `tool_name`, `field`, `previous_value`, `current_value`, `suspected_canonical`, `message`).

## Out of scope
- `${VAR}` expansion errors, `cwd` for stdio servers, Windows `.cmd` shims, SSE wire protocol,
  `tools/list` pagination, `resources`/`prompts` for stdio, changing the severity gate.

## Phases
- P1 domain + service (T001–T006) → P2 loader (T007–T008) → P3 fetcher (T009–T011) →
  P4 CLI + acceptance + secrets + exit codes (T012–T017) → P5 docs + gates (T018–T019).
