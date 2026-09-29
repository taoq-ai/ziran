# Analyzing production traces

`ziran analyze-traces` ingests production traces (OTel JSONL or Langfuse), reconstructs per-session tool-call sequences, and flags sequences that match dangerous tool chains. See [OTel tracing](otel-tracing.md) for how to export traces.

```bash
ziran analyze-traces --source otel --input traces.jsonl --out ./reports
```

## Claude Code span contract (version 1)

A Claude Code `PostToolUse` hook can record each tool call as one line of OTLP JSON. `analyze-traces --source otel` reads that file directly. This is the stable shape, version 1:

| Field | Where | Required | Meaning |
|---|---|---|---|
| `service.name` | resource attribute | yes | Emitting agent, e.g. `claude-code`. Reported as the agent name. |
| `traceId` | span | yes | 32 hex characters. Used for grouping only when no `session.id` is present. |
| `spanId` | span | yes | 16 hex characters. |
| `name` | span | yes | Span name; use the tool name. |
| `startTimeUnixNano` | span | yes | Nanosecond epoch, as a string. Orders calls within a session. |
| `endTimeUnixNano` | span | yes | Nanosecond epoch, as a string. May equal the start time. |
| `session.id` | span attribute | yes | The Claude Code `session_id`. This is the session key. |
| `gen_ai.tool.name` | span attribute | yes | Tool name verbatim (`Read`, `Bash`, `mcp__slack__slack_send_message`, ...). |
| `gen_ai.tool.arguments` | span attribute | no | The tool's `tool_input` as a JSON string. |

- Each line is one `ResourceSpans` object (`{"resourceSpans": [...]}`).
- **Grouping**: spans are grouped into sessions by the span attribute `session.id`, then the resource attribute `session.id`, then `traceId`. The chosen key becomes the reported `session_id`. Spans with none of the three are skipped. Two sessions that share a `traceId` are never merged.
- **Compatibility**: unknown attributes are ignored. Version 1 changes are additive only. Renaming or removing a field, or changing the grouping rule, makes a version 2.
- Claude Code tool names are mapped to capabilities by the alias table in [tool chains](../concepts/tool-chains.md#claude-code-tool-names), so `Read` followed by `WebFetch` in one session is a critical `data_exfiltration` chain.

Example line (a `Read` of `.env`):

```json
{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeSpans":[{"spans":[{"traceId":"4bf92f3577b34da6a3ce929d0e0e4736","spanId":"0000000000000001","name":"Read","startTimeUnixNano":"1760000000000000000","endTimeUnixNano":"1760000000250000000","attributes":[{"key":"session.id","value":{"stringValue":"cc-session-exfil"}},{"key":"gen_ai.tool.name","value":{"stringValue":"Read"}},{"key":"gen_ai.tool.arguments","value":{"stringValue":"{\"file_path\": \"/repo/.env\"}"}}]}]}]}]}
```

### Command evidence and redaction

For shell tools (`Bash`), the `command` string of each call in the matched chain is kept as evidence. Secrets are replaced with `[REDACTED]` using the SA001 secret rules plus rules for unquoted `NAME=value` assignments, `--secret-flag value` pairs and URL credentials. Each command is then cut to 500 characters, and at most 10 commands are kept per session. No other argument value (file paths, URLs, prompts) is written to reports or alerts. Redaction is pattern-based, so secrets in unusual shapes can still get through.

## JSON output

With `--format json` (the default), the report is written to `<--out>/trace_analysis.json`. Fields that are stable for automation:

| Field | Meaning |
|---|---|
| `critical_chain_count` | Number of distinct critical chains. |
| `metadata.sessions_analyzed` | Number of sessions read from the input. |
| `dangerous_tool_chains[].tools` | Tool names as they appeared in the trace. |
| `dangerous_tool_chains[].risk_level` | `critical`, `high`, `medium` or `low`. |
| `dangerous_tool_chains[].vulnerability_type` | e.g. `data_exfiltration`, `unrestricted_execution`. |
| `dangerous_tool_chains[].risk_score` | Float score. |
| `dangerous_tool_chains[].evidence.sessions[].session_id` | Each session the chain was seen in. |
| `dangerous_tool_chains[].evidence.sessions[].commands` | Redacted shell commands from that session (may be empty). |

```json
{
  "critical_chain_count": 1,
  "metadata": {"sessions_analyzed": 1, "trace_source": "otel"},
  "dangerous_tool_chains": [
    {
      "tools": ["Read", "WebFetch"],
      "risk_level": "critical",
      "vulnerability_type": "data_exfiltration",
      "risk_score": 1.0,
      "evidence": {
        "edge_exists": true,
        "sessions": [{"session_id": "cc-session-exfil", "commands": []}]
      }
    }
  ]
}
```

## Alerting

By default the command writes a report file. With `--alert`, dangerous-chain matches are also delivered to the notification sinks declared in a config file, so the operator who can fix the issue hears about it.

```bash
ziran analyze-traces --source otel --input traces.jsonl \
  --alert --config alerts.yaml
```

`alerts.yaml` carries an `alerts:` block (the same schema used by `watch-registry`). Secrets are resolved from the environment via the `!env` tag — never commit them:

```yaml
alerts:
  - kind: github_issue
    repo: myorg/ai-agent-infra
    token: !env GH_TOKEN
    labels: [trace-finding, security]
    severity_floor: high
  - kind: slack
    webhook_url: !env SLACK_WEBHOOK_URL
    severity_floor: medium
```

Each filed GitHub issue includes the observed tool sequence, the session ID, the trace source, the (inherited) severity, and a suggested remediation when available.

### Per-session vs. digest

- Default: one issue per `(chain, session)` execution.
- `--digest`: aggregate all matches from the run into a single digest issue.

### Deduplication

Issues are deduplicated by a stateless fingerprint embedded in the issue body (`(tool-chain, session)` for per-session, the chain set for a digest). Re-running on the same traces opens **no** new issues. The digest fingerprint excludes the run date, so an unchanged set of chains reuses the same digest issue across days.

### Correlating pre-deploy findings

Pass `--predeploy-result scan.json` (a prior `CampaignResult`) to correlate production matches against pre-deploy findings by tool sequence. Matched findings inherit the pre-deploy severity and remediation, and the issue links back to the pre-deploy finding.

### Previewing

`--dry-run-alerts` prints what each sink would send and performs zero network I/O.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Input was read and no critical chain matched. |
| `1` | At least one critical chain matched. The report is written and alerts are sent first. |
| `2` | Could not run or finish: missing or unreadable input, a directory as input, a file with no valid JSON line, `--source otel` without `--input`, `--alert` without `--config`, invalid config, alert delivery failure, or any unexpected error. One `Error:` line is printed; add `-v` for the traceback. |

When several apply, `2` wins over `1`, and `1` wins over `0`.

!!! warning "Changed in this release"
    Earlier versions exited `0` when critical chains matched, and `1` on usage errors. CI jobs that run `analyze-traces` now fail on critical matches.
