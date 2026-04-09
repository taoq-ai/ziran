# CLI Contract: `ziran watch-registry`

## Synopsis

```
ziran watch-registry --config <path> [--snapshot-dir <dir>] [--out <dir>] [--format <format>] [--verbose]
```

## Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `--config` | `Path` | Yes | — | Registry config YAML file |
| `--snapshot-dir` | `Path` | No | `.ziran/snapshots/` | Directory for manifest snapshots |
| `--out` | `Path` | No | `./reports/` | Output directory for drift report |
| `--format` | `Choice` | No | `json` | Report format: `json`, `markdown`, `html` |
| `--verbose` | `Flag` | No | `False` | Show per-server details |

## Registry Config YAML Format

```yaml
servers:
  - name: "my-mcp-server"
    url: "http://localhost:3000"
    transport: "streamable-http"      # "stdio" | "sse" | "streamable-http"
  - name: "another-server"
    url: "http://mcp.example.com"
    transport: "sse"

allowlist:
  - "official-weather-server"
  - "official-calendar-server"

exemptions:
  - "my-weather-fork"                 # Not a typosquat; explicit exemption
```

## Behavior

1. Load registry config from `--config`.
2. For each server:
   a. Fetch current manifest via MCP protocol handler.
   b. Load previous snapshot from `--snapshot-dir` (if exists).
   c. Diff manifests: detect added/removed tools, description changes, schema changes, permission changes.
   d. Save current manifest as new snapshot.
3. Run typosquatting detection: compare all server names against `allowlist`, excluding `exemptions`.
4. Emit drift and typosquat findings to `--out/` in the requested format.
5. Print summary: `Checked N servers. Found M drift events, K typosquat warnings.`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (including zero findings) |
| 1 | Error (config not found, invalid YAML) |
| 2 | Findings above severity threshold (for CI gate use) |

## Error Handling

- If a server is unreachable, log a warning and skip it. Do NOT update its snapshot. Do NOT emit a "tool removed" finding.
- If the snapshot directory does not exist, create it.
- First run (no prior snapshots): store the baseline snapshot and report zero drift findings.

## Severity Scoring

| Drift Type | Default Severity |
|------------|-----------------|
| `description_changed` | `high` (potential prompt injection) |
| `tool_added` | `medium` (capability escalation) |
| `tool_removed` | `low` (informational) |
| `schema_changed` | `medium` |
| `permission_changed` | `high` |
| `typosquat` (distance 1) | `high` |
| `typosquat` (distance 2) | `medium` |
