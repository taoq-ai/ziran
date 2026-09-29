# CLI Reference

ZIRAN provides 8 commands for scanning, reporting, and CI/CD integration.

## Global Options

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Enable debug logging |
| `--log-file PATH` | Write logs to file |
| `--log-format [json\|text]` | Log output format (default: text on a TTY, json otherwise). See [Observability](observability.md). |
| `--version` | Show version |
| `--help` | Show help |

## Commands

### `ziran scan`

Run a security scan campaign against an AI agent.

```
ziran scan [OPTIONS]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--framework` | Yes\* | — | Agent framework: `langchain`, `crewai`, `bedrock` |
| `--agent-path` | Yes\* | — | Path to agent code/config file |
| `--target` | Yes\* | — | YAML target config for remote scanning |
| `--protocol` | No | `auto` | Protocol override: `rest`, `openai`, `mcp`, `a2a`, `auto` |
| `--phases` | No | all core | Specific phases to run |
| `--coverage` | No | `standard` | Coverage level: `essential`, `standard`, `comprehensive` |
| `--output`, `-o` | No | `ziran_results` | Output directory |
| `--custom-attacks` | No | — | Directory with custom YAML attack vectors |
| `--stop-on-critical` | No | `true` | Stop if critical vulnerability found |
| `--concurrency` | No | `5` | Max concurrent attacks |
| `--strategy` | No | `fixed` | Campaign strategy: `fixed`, `adaptive`, `llm-adaptive` |
| `--streaming` | No | `false` | Enable real-time SSE/WebSocket response streaming |
| `--llm-provider` | No | — | LLM provider for AI-powered features |
| `--llm-model` | No | — | LLM model name (e.g. `gpt-4o`, `claude-sonnet-4-20250514`) |
| `--encoding` | No | — | Prompt encoding/obfuscation: `base64`, `rot13`, `leetspeak`, `homoglyph`, `hex`, `whitespace`, `mixed_case`, `payload_split`. Repeatable. |
| `--otel` | No | `false` | Enable OpenTelemetry tracing (requires `ziran[otel]`). Exports spans to console. |
| `--attack-timeout` | No | `60` | Per-attack timeout in seconds |
| `--phase-timeout` | No | `300` | Per-phase timeout in seconds |

\* Either `--framework` + `--agent-path` (local) or `--target` (remote) is required.

**Examples:**

```bash
# Local agent
ziran scan --framework langchain --agent-path agent.py

# Remote agent
ziran scan --target target.yaml

# Full audit with custom vectors
ziran scan --target target.yaml --coverage comprehensive \
  --custom-attacks ./my_attacks/ --concurrency 10

# Adaptive campaign
ziran scan --target target.yaml --strategy adaptive

# LLM-driven adaptive with streaming
ziran scan --target target.yaml --strategy llm-adaptive --streaming

# Scan with Base64 and ROT13 encoding variants
ziran scan --target target.yaml --encoding base64 --encoding rot13

# Scan with OpenTelemetry tracing
ziran scan --target target.yaml --otel
```

---

### `ziran multi-agent-scan`

Scan a multi-agent system — discovers topology and runs cross-agent attacks.

```
ziran multi-agent-scan [OPTIONS]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--target` | Yes | — | YAML target config for the entry-point agent |
| `--coverage` | No | `standard` | Coverage level: `essential`, `standard`, `comprehensive` |
| `--concurrency` | No | `5` | Max concurrent attacks |
| `--skip-individual` | No | `false` | Skip individual agent scans |
| `--output`, `-o` | No | `ziran_results` | Output directory |

**Examples:**

```bash
# Scan a multi-agent system
ziran multi-agent-scan --target target.yaml

# Full coverage, skip individual scans
ziran multi-agent-scan --target target.yaml --coverage comprehensive --skip-individual
```

---

### `ziran discover`

Discover agent capabilities without running attacks (Phase 1 only).

```
ziran discover [OPTIONS] [AGENT_PATH]
```

| Option | Description |
|--------|-------------|
| `--framework` | Agent framework: `langchain`, `crewai`, `bedrock` |
| `--target` | YAML target config for remote discovery |
| `--protocol` | Protocol override |

**Examples:**

```bash
ziran discover --framework langchain agent.py
ziran discover --target target.yaml
```

---

### `ziran library`

Browse the attack vector library.

```
ziran library [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--list` | List all attack vectors |
| `--category` | Filter by category |
| `--phase` | Filter by target phase |
| `--owasp` | Filter by OWASP LLM category (`LLM01`–`LLM10`) |
| `--custom-attacks` | Include custom YAML vectors |

**Examples:**

```bash
ziran library --list
ziran library --category prompt_injection
ziran library --owasp LLM01
ziran library --phase vulnerability_discovery
```

---

### `ziran report`

Regenerate a report from a saved campaign result.

```
ziran report RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `markdown`, `json`, `html` |

**Examples:**

```bash
ziran report results.json --format html
ziran report results.json --format markdown
```

---

### `ziran poc`

Generate proof-of-concept exploits from scan results.

```
ziran poc RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | `.` | Output directory |
| `--format` | `all` | PoC format: `python`, `curl`, `markdown`, `all` |

**Examples:**

```bash
ziran poc results.json --format python --output ./pocs/
ziran poc results.json --format curl
```

---

### `ziran policy`

Evaluate scan results against a policy file.

```
ziran policy RESULT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--policy`, `-p` | Path to YAML policy file |

**Example:**

```bash
ziran policy results.json --policy production-policy.yaml
```

---

### `ziran audit`

Run static analysis on agent source code (no LLM required).

```
ziran audit PATH [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--severity` | Minimum severity filter: `critical`, `high`, `medium`, `low` |
| `--format` | Output format: `text` (default) or `json` |

**Examples:**

```bash
ziran audit my_agent.py
ziran audit ./src/agents/ --severity high
ziran audit ./src/agents/ --format json --severity high
```

With `--format json`, stdout is a single JSON document (logs go to stderr). The matched
source line is never included, so secrets that trigger a finding are not echoed.

```json
{
  "files_analyzed": 1,
  "findings": [
    {
      "rule": "SA001",
      "severity": "critical",
      "file": "my_agent.py",
      "line": 1,
      "message": "..."
    }
  ]
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No failing findings |
| `1` | Failing findings: with `--format json --severity X`, any finding at or above `X`; otherwise any `critical` finding |
| `2` | Usage error (for example `PATH` does not exist or an invalid option) |

Text mode (the default) keeps its existing behaviour and exits `1` only on `critical`
findings, even when `--severity` is lower.

---

### `ziran watch-registry`

Snapshot the `tools/list` of MCP servers and report drift (tools added or removed, description,
schema or permission changes), typosquats and poisoned tool metadata.

```
ziran watch-registry (--config FILE | --from-claude-config FILE) [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | — | Registry config YAML (`servers`, `allowlist`, `exemptions`, `snapshot_dir`, `alerts`) |
| `--from-claude-config` | — | Claude Code MCP config JSON; mutually exclusive with `--config` |
| `--snapshot-dir` | `.ziran/snapshots` | Where one `<server>.json` baseline per server is stored |
| `--out` | `./reports` | Report directory (`registry-watch-report.json` or `.md`) |
| `--format` | `json` | `json` or `markdown` |
| `--dry-run-alerts` | off | Preview alert payloads without contacting Slack/GitHub |
| `--verbose`, `-v` | off | Debug logging |

Exactly one of `--config` / `--from-claude-config` is required.

**Claude Code config shapes.** `--from-claude-config` accepts a project `.mcp.json`
(`{"mcpServers": {...}}`), a plugin `.mcp.json` (flat `{"<name>": {...}}` map) and user settings
JSON (only the top-level `mcpServers` key is read). Per server:

| Fields | Transport |
|--------|-----------|
| `command`, optional `args`, `env`, `type: "stdio"` | stdio: ZIRAN launches the command (inheriting its working directory) and calls `initialize` + `tools/list`, 30 s timeout |
| `url`, optional `type: "http"`, `headers` | streamable-http |
| `url`, `type: "sse"`, optional `headers` | sse (fetched with the same HTTP JSON-RPC POST as `--config`) |

Any other `type`, or an entry with neither `command` nor `url`, is a config error.
`${VAR}` and `${VAR:-default}` are expanded in every string from the environment;
`${CLAUDE_PLUGIN_ROOT}` defaults to the config file's directory. An unset placeholder with no
default is left as written.

**Secrets.** Values of `env` and `headers` are used only to start or reach the server. They are
never written to snapshots or reports, never printed and never logged; logs record only the key
names (`claude_mcp_server_loaded` event with `env_keys` / `header_keys`). The stdio server's
stderr is discarded.

**First registration.** When a server has no stored snapshot, its `tools/list` is scanned by the
MCP metadata analyzer; suspicious descriptions or parameter hints are reported as
`tool_poisoning` findings (severity `critical`, `high` or `medium`). Later runs diff against the
baseline.

**Exit codes** (command-wide, precedence `2` > `1` > `0`):

| Code | Meaning |
|------|---------|
| `0` | Every server processed; no `high`/`critical` finding (medium/low drift is still reported) |
| `1` | Every server processed; at least one `high`/`critical` finding (drift, typosquat or `tool_poisoning`) |
| `2` | Could not run completely: usage error, unreadable or invalid config, at least one unreachable server or timeout (names printed to stderr), or alert delivery failure |

An unreachable server never overwrites its stored snapshot; the report is still written for the
servers that were reached.

**JSON report.** `registry-watch-report.json` is a list of findings, each with `server_name`,
`drift_type` (`tool_added`, `tool_removed`, `description_changed`, `schema_changed`,
`permission_changed`, `typosquat`, `tool_poisoning`), `severity`, `tool_name`, `field`,
`previous_value`, `current_value`, `suspected_canonical` and `message`.

**Example:**

```bash
ziran watch-registry --from-claude-config .mcp.json \
  --snapshot-dir .ziran/snapshots --out reports --format json
```

---

### `ziran ci`

CI/CD quality gate — evaluate results and emit integration outputs.

```
ziran ci RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--gate-config`, `-g` | — | Quality gate YAML config |
| `--policy`, `-p` | — | Policy file for rule evaluation |
| `--sarif` | — | Write SARIF v2.1.0 report to path |
| `--github-annotations` | `true` | Emit GitHub Actions annotations |
| `--github-summary` | `true` | Write GitHub Actions step summary |

**Examples:**

```bash
# Simple gate check
ziran ci results.json --gate-config gate.yaml

# Full CI pipeline
ziran ci results.json \
  --gate-config gate.yaml \
  --policy policy.yaml \
  --sarif results.sarif \
  --github-annotations \
  --github-summary
```
