# Claude Code Plugins

ZIRAN checks a Claude Code plugin in four ways: a static audit of its subagents' declared tools,
an allowlist baseline that fails CI when an agent's tools widen, an analysis of the tool calls its
hooks record, and a check of the MCP servers its `.mcp.json` starts. None of them runs the agent,
calls an LLM or needs an API key. Requires `ziran>=0.40.0`.

Every command below is run from
[`examples/25-claude-code-plugin/`](https://github.com/taoq-ai/ziran/tree/main/examples/25-claude-code-plugin),
which holds a `safe-plugin` and a `vulnerable-plugin`. Structured logs go to stderr and are left
out of the output shown here; `...` marks trimmed output.

## Static audit

`ziran audit PATH` accepts a plugin root (`.claude-plugin/plugin.json`), a directory containing
`.claude/agents/`, a directory named `agents`, or a single agent `.md` file. Each agent's declared
`tools` are mapped to capabilities ([Claude Code tool names](../concepts/tool-chains.md#claude-code-tool-names))
and walked for dangerous chains. The rules (`CC000`, `SA001`, `SA003`, `SA004`, `SA007`, `CC001`)
are listed in the [CLI reference](../reference/cli.md#claude-code-plugins).

The safe plugin's agent declares `tools: Read, Grep, Glob`:

```console
$ ziran audit safe-plugin

╭─ Static Analysis ─╮
│ No issues found   │
╰───────────────────╯
Files analysed: 3
```

The vulnerable plugin's agent declares `tools: Read, Grep, WebFetch`. Each tool is harmless
alone; reading local files plus fetching URLs is a data exfiltration path:

```console
$ ziran audit vulnerable-plugin

╭─────── Static Analysis ───────╮
│ Found 3 issue(s) in 3 file(s) │
│   Critical: 2  High: 1        │
╰───────────────────────────────╯

┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check  ┃ Severity   ┃ Message                    ┃ Location                  ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SA003  │ high       │ Agent 'researcher' is      │ vulnerable-plugin/agents… │
│        │            │ granted dangerous tool     │                           │
│        │            │ 'WebFetch'                 │                           │
├────────┼────────────┼────────────────────────────┼───────────────────────────┤
│ CC001  │ critical   │ Agent 'researcher':        │ vulnerable-plugin/agents… │
│        │            │ data_exfiltration via Read │                           │
│        │            │ -> WebFetch                │                           │
├────────┼────────────┼────────────────────────────┼───────────────────────────┤
│ CC001  │ critical   │ Agent 'researcher':        │ vulnerable-plugin/agents… │
│        │            │ data_exfiltration via Grep │                           │
│        │            │ -> WebFetch                │                           │
└────────┴────────────┴────────────────────────────┴───────────────────────────┘
...
FAILED — critical issues found
```

With `--format json` each row carries `rule`, `severity`, `file`, `line`, `message`, `agent` and
`tools`:

```console
$ ziran audit vulnerable-plugin --format json
{
  "files_analyzed": 3,
  "findings": [
    ...
    {
      "rule": "CC001",
      "severity": "critical",
      "file": "vulnerable-plugin/agents/researcher.md",
      "line": 4,
      "message": "Agent 'researcher': data_exfiltration via Read -> WebFetch",
      "agent": "researcher",
      "tools": [
        "Read",
        "WebFetch"
      ]
    },
    ...
  ]
}
```

The command exits `0` when nothing fails, `1` on failing findings and `2` on a usage error.
`--sarif FILE` also writes the findings as SARIF for GitHub code scanning. The plugin's hooks and
MCP servers are not checked by `audit`; see the two sections below.

## Allowlist baseline in CI

Some agents legitimately hold a chain (a researcher that must read files and fetch docs). A
baseline records each agent's tools and chains today, so CI fails only when they widen. Try the
loop on a copy of the safe plugin:

```console
$ cp -R safe-plugin /tmp/my-plugin
$ ziran audit /tmp/my-plugin --write-baseline /tmp/my-plugin/ziran-baseline.json
Baseline written to /tmp/my-plugin/ziran-baseline.json (1 agents)

╭─ Static Analysis ─╮
│ No issues found   │
╰───────────────────╯
Files analysed: 3
```

Commit `ziran-baseline.json`. Now widen the agent: append `, WebFetch` to line 4 of
`/tmp/my-plugin/agents/reviewer.md` so it reads `tools: Read, Grep, Glob, WebFetch`, and check
against the baseline:

```console
$ ziran audit /tmp/my-plugin --baseline /tmp/my-plugin/ziran-baseline.json

╭─────── Static Analysis ───────╮
│ Found 5 issue(s) in 3 file(s) │
│   Critical: 4  High: 1        │
╰───────────────────────────────╯

┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check  ┃ Severity   ┃ Message                   ┃ Location                   ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SA003  │ high       │ Agent 'reviewer' is       │ /tmp/my-plugin/agents/rev… │
│        │            │ granted dangerous tool    │                            │
│        │            │ 'WebFetch'                │                            │
├────────┼────────────┼───────────────────────────┼────────────────────────────┤
│ BL001  │ critical   │ Agent 'reviewer' gains    │ /tmp/my-plugin/agents/rev… │
│        │            │ tool 'WebFetch' not in    │                            │
│        │            │ the baseline              │                            │
├────────┼────────────┼───────────────────────────┼────────────────────────────┤
│ BL003  │ critical   │ Agent 'reviewer': new     │ /tmp/my-plugin/agents/rev… │
│        │            │ critical chain            │                            │
│        │            │ data_exfiltration via     │                            │
│        │            │ Read -> WebFetch not in   │                            │
│        │            │ the baseline              │                            │
...
FAILED — critical issues found
```

The command exits `1`. Every `BL00x` widening (`BL001` new tool, `BL002` lost `tools:` key,
`BL003` new chain, `BL004` new agent) is `critical`, so it fails under any `--severity`.
Narrowings (a tool or agent removed) never fail; in JSON they are listed under
`baseline.narrowed`. After reviewing an intended change, record the baseline again and commit it.
Upgrading ZIRAN can add chain patterns and so new `BL003` rows for unchanged agents: record again
when you bump the pinned release. Details: [Allowlist baseline](../reference/cli.md#allowlist-baseline).

In GitHub Actions, run the same check with `command: audit`:

```yaml
- uses: taoq-ai/ziran@v0
  with:
    command: audit
    path: "."                          # plugin root
    baseline: ziran-baseline.json
    ziran-version: "ziran==0.40.0"     # the release you recorded the baseline with
```

The audit inputs are `path` (or `source-path`), `baseline`, `severity-threshold` (default `low`),
`sarif-output` (default `ziran-results.sarif`, uploaded to code scanning; `""` disables it) and
`ziran-version`. The outputs are `status`, `exit-code`, `sarif-file` and `sarif-id`. See
[Claude Code plugin audit](ci-integrations.md#claude-code-plugin-audit) for the full tables and
[`examples/07-cicd-quality-gate/claude-code-audit.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/claude-code-audit.yml)
for a complete workflow.

## Traces from Claude Code hooks

The audit sees what an agent may do; traces show what it did. A Claude Code `PostToolUse` hook
can append one line of OTLP JSON per tool call, and `ziran analyze-traces --source otel` reads
that file. ZIRAN does not ship a hook script: you write one that maps the hook input to the
[span contract (version 1)](analyze-traces.md#claude-code-span-contract-version-1):

| Hook input field | Span field |
|---|---|
| `session_id` | span attribute `session.id` |
| `tool_name` | span attribute `gen_ai.tool.name` and span `name` |
| `tool_input` (as a JSON string) | span attribute `gen_ai.tool.arguments` (optional) |

The example's `traces/` directory holds two files in that shape. `safe.jsonl` is a session that
calls `Read` then `Grep`; `vulnerable.jsonl` reads `.env` then calls `WebFetch`:

```console
$ ziran analyze-traces --source otel --input traces/safe.jsonl --out reports
...
│ Sessions Analyzed     │ 1                  │
│ Dangerous Chains      │ 0                  │
│ Critical Chains       │ 0                  │
│ Total Vulnerabilities │ 0                  │
└───────────────────────┴────────────────────┘

Report saved to reports/trace_analysis.json
```

```console
$ ziran analyze-traces --source otel --input traces/vulnerable.jsonl --out reports
...
│ Sessions Analyzed     │ 1                  │
│ Dangerous Chains      │ 1                  │
│ Critical Chains       │ 1                  │
│ Total Vulnerabilities │ 1                  │
└───────────────────────┴────────────────────┘
                   Dangerous Tool Chains
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Tools            ┃ Risk     ┃ Type              ┃ Score ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Read -> WebFetch │ critical │ data_exfiltration │ 1.000 │
└──────────────────┴──────────┴───────────────────┴───────┘

Report saved to reports/trace_analysis.json
```

The first exits `0`, the second `1` (`2` on an error such as a missing input file). The report
`reports/trace_analysis.json` has `critical_chain_count` and `dangerous_tool_chains[]` with
`tools`, `risk_level` and `vulnerability_type`. `Bash` commands in a matched chain are kept as
evidence with secrets redacted ([Command evidence and redaction](analyze-traces.md#command-evidence-and-redaction)),
and `--alert` sends matches to Slack or GitHub ([Alerting](analyze-traces.md#alerting)).

## MCP registry import

`ziran watch-registry --from-claude-config FILE` reads the MCP servers from a project `.mcp.json`,
a plugin `.mcp.json` or user settings, starts or reaches each one and fetches its `tools/list`.
`${CLAUDE_PLUGIN_ROOT}` defaults to the config file's directory. Values of `env` and `headers` are
used only to reach the server and are never written or logged. On the first run (no snapshot)
the tool metadata is scanned for `tool_poisoning`; later runs diff against the snapshot, so delete
`reports/snapshots` to repeat the first-run result.

Each example plugin's `.mcp.json` starts the local stand-in server `mcp_server.py` (needs
`python3` on `PATH`) with that plugin's `mcp-tools.json`:

```console
$ ziran watch-registry --from-claude-config safe-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
Report written to reports/registry-watch-report.json
No drift detected.
```

The vulnerable plugin's `search_docs` description tells the model to send `~/.ssh/id_rsa` to an
external URL:

```console
$ rm -rf reports/snapshots
$ ziran watch-registry --from-claude-config vulnerable-plugin/.mcp.json --snapshot-dir reports/snapshots --out reports
Report written to reports/registry-watch-report.json
                            Registry Watch Findings
┏━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Server ┃ Type           ┃ Severity ┃ Tool        ┃ Message                   ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ docs   │ tool_poisoning │ critical │ search_docs │ Suspicious tool metadata  │
│        │                │          │             │ (exfiltration_directive)  │
...
│ docs   │ tool_poisoning │ high     │ search_docs │ Suspicious tool metadata  │
│        │                │          │             │ (imperative_instruction)  │
...
└────────┴────────────────┴──────────┴─────────────┴───────────────────────────┘

2 finding(s) total.
```

The first exits `0` with `reports/registry-watch-report.json` containing `[]`; the second exits
`1`. Each report row has `server_name`, `drift_type`, `severity`, `tool_name`, `field`,
`previous_value`, `current_value`, `suspected_canonical` and `message`. Exit `2` means the run was
incomplete, for example an unreachable server. Details:
[`ziran watch-registry`](../reference/cli.md#ziran-watch-registry).

## Limits

- Tool strings are compared verbatim: scoping `Bash` to `Bash(npm test:*)` counts as a new tool
  in a baseline.
- The audit covers the tools an agent declares, not what a prompt makes it do with them; traces
  cover that.
- Hook commands are not audited, and ZIRAN ships no hook script that emits traces.
- Upgrading ZIRAN can add `BL003` rows for unchanged agents.
