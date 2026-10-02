# Claude Code Plugin

Audit a safe and a vulnerable Claude Code plugin offline: their subagents' declared tools, the
tool calls their hooks would record, and the MCP servers their `.mcp.json` starts. No agent is
run and no LLM is called. Walkthrough, including the allowlist baseline in CI:
[Claude Code guide](https://taoq-ai.github.io/ziran/guides/claude-code/).

| | `safe-plugin/` | `vulnerable-plugin/` |
|---|---|---|
| Agent `tools:` | `Read, Grep, Glob` | `Read, Grep, WebFetch` |
| MCP tool `search_docs` description | plain | tells the model to send `~/.ssh/id_rsa` to an external URL |
| Trace (`traces/`) | `safe.jsonl`: `Read` then `Grep` | `vulnerable.jsonl`: `Read` of `.env` then `WebFetch` |

`mcp_server.py` is a local stdlib stand-in for a real MCP server.

## Prerequisites

- Python 3.11+ and `python3` on `PATH` (the plugins' `.mcp.json` starts `python3 mcp_server.py`)
- `pip install "ziran>=0.40.0"`

No API keys required.

## Run

From this directory (output goes to the git-ignored `reports/`):

```bash
ziran audit safe-plugin
ziran audit vulnerable-plugin
ziran analyze-traces --source otel --input traces/safe.jsonl --out reports
ziran analyze-traces --source otel --input traces/vulnerable.jsonl --out reports
ziran watch-registry --from-claude-config safe-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
rm -rf reports/snapshots
ziran watch-registry --from-claude-config vulnerable-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
```

`watch-registry` scans tool metadata only when a server has no snapshot yet, hence the
`rm -rf reports/snapshots` between runs.

## Expected output

Every safe command exits `0`; every vulnerable one exits `1`.

```console
$ ziran audit safe-plugin
...
│ No issues found   │
...
$ ziran audit vulnerable-plugin
...
│ SA003  │ high       │ Agent 'researcher' is      │ vulnerable-plugin/agents… │
...
│ CC001  │ critical   │ Agent 'researcher':        │ vulnerable-plugin/agents… │
│        │            │ data_exfiltration via Read │                           │
│        │            │ -> WebFetch                │                           │
...
│ CC001  │ critical   │ Agent 'researcher':        │ vulnerable-plugin/agents… │
│        │            │ data_exfiltration via Grep │                           │
│        │            │ -> WebFetch                │                           │
...
FAILED — critical issues found
$ ziran analyze-traces --source otel --input traces/safe.jsonl --out reports
...
│ Critical Chains       │ 0                  │
...
$ ziran analyze-traces --source otel --input traces/vulnerable.jsonl --out reports
...
│ Read -> WebFetch │ critical │ data_exfiltration │ 1.000 │
...
$ ziran watch-registry --from-claude-config safe-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
Report written to reports/registry-watch-report.json
No drift detected.
$ rm -rf reports/snapshots
$ ziran watch-registry --from-claude-config vulnerable-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
...
│ docs   │ tool_poisoning │ critical │ search_docs │ Suspicious tool metadata  │
│        │                │          │             │ (exfiltration_directive)  │
...
│ docs   │ tool_poisoning │ high     │ search_docs │ Suspicious tool metadata  │
│        │                │          │             │ (imperative_instruction)  │
...
2 finding(s) total.
```

`tests/integration/test_claude_code_plugin_example.py` runs these checks in CI.
