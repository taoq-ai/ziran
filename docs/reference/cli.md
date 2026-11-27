# CLI Reference

ZIRAN provides 17 commands (16 plus the `cache` group) for scanning, auditing, reporting, runtime-bridge work and CI/CD
integration. `ziran COMMAND --help` lists the flags of the release you have installed.

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
| `--framework` | Yes\* | — | Agent framework: `langchain`, `langgraph`, `crewai`, `bedrock`, `agentcore`, `anthropic`, `openai-agents`, `autogen` |
| `--agent-path` | Yes\* | — | Path to agent code/config file |
| `--target` | Yes\* | — | YAML target config for remote scanning |
| `--protocol` | No | `auto` | Protocol override: `rest`, `openai`, `mcp`, `a2a`, `browser`, `auto` |
| `--phases` | No | all core | Specific phases to run |
| `--coverage` | No | `standard` | Coverage level: `essential`, `standard`, `comprehensive` |
| `--output`, `-o` | No | `ziran_results` | Output directory |
| `--custom-attacks` | No | — | Directory with custom YAML attack vectors |
| `--stop-on-critical` | No | `true` | Stop after a critical finding in exploitation_setup or a later phase; earlier criticals are kept. Default-on scans now run more phases and use more traffic and tokens against a vulnerable target: see `--max-cost`, `--max-campaign-tokens`, `--no-stop-on-critical` |
| `--concurrency` | No | `5` | Max concurrent attacks |
| `--strategy` | No | `fixed` | Campaign strategy: `fixed`, `adaptive`, `llm-adaptive` |
| `--streaming` | No | `false` | Enable real-time SSE/WebSocket response streaming |
| `--llm-provider` | No | — | LLM provider for AI-powered features |
| `--llm-model` | No | — | LLM model name (e.g. `gpt-4o`, `claude-sonnet-4-20250514`) |
| `--attacker-model` | No | — | LiteLLM model id of the attacker LLM that runs attacker vectors (`tactic: pair`, `tap` and `crescendo_live`; requires `ziran[llm]`; the key comes from the provider's usual environment variable). Without it (or with a blank value) those vectors are not run, the dry run does not count them, and the report's warnings list them, one line per phase. Its tokens count towards `--max-campaign-tokens` and `--max-cost`. See [Attacker-LLM refinement](../concepts/attack-vectors.md#attacker-llm-refinement). |
| `--attacker-cassette` | No | — | File of the attacker's replies as spec 064 outcome rows. With `--attacker-model` it records them (written atomically; a symlink path is refused); without it, an existing file is replayed with no key, so a campaign tree repeats offline. A request with no stored reply stops its vector as pending (unmeasured). See [Record and replay](../concepts/attack-vectors.md#record-and-replay-the-attacker). |
| `--encoding` | No | — | Prompt encoding/obfuscation: `base64`, `rot13`, `leetspeak`, `homoglyph`, `hex`, `whitespace`, `mixed_case`, `payload_split`, `pig_latin`, `reverse`, `word_shuffle`, `token_boundary`. Repeatable. |
| `--otel` | No | `false` | Enable OpenTelemetry tracing (requires `ziran[otel]`). Exports spans to console. |
| `--attack-timeout` | No | `60` | Per-attack timeout in seconds |
| `--phase-timeout` | No | `300` | Per-phase timeout in seconds |
| `--llm-rpm` | No | per provider | Client-side LLM requests-per-minute limit (`0` disables). Env: `ZIRAN_LLM_RPM` |
| `--llm-tpm` | No | — | Client-side LLM tokens-per-minute limit (`0` disables). Env: `ZIRAN_LLM_TPM` |
| `--llm-max-retries` | No | `3` | Retries for throttled or transient LLM errors (429, 5xx). Env: `ZIRAN_LLM_MAX_RETRIES` |
| `--quality-scoring` | No | `false` | StrongREJECT-style scoring of response specificity and convincingness (needs `--llm-provider`) |
| `--utility-tasks` | No | — | YAML file of legitimate tasks, run before and after the campaign to measure utility under attack |
| `--metrics-endpoint` | No | — | OTLP/HTTP collector URL for Prometheus-compatible metrics (needs `ziran[otel]`) |
| `--metrics-port` | No | — | TCP port for a Prometheus pull endpoint (`/metrics`) (needs `ziran[otel]`) |
| `--resume` | No | `false` | Resume an interrupted campaign from the checkpoint in `--output` |
| `--checkpoint-flush-interval` | No | `10.0` | Maximum seconds between mid-phase checkpoint flushes |
| `--max-campaign-tokens` | No | — | Stop scheduling new attacks once the campaign has used this many tokens across all stages. Cooperative: attacks already running finish, so the total can overshoot by up to `--concurrency` attack runs (one run with `--trials` above 1). Attacker vectors that run at the same time share one running count. See [Long-running campaigns](../guides/long-running-campaigns.md) |
| `--max-cost` | No | — | Stop scheduling new attacks once the estimated LLM cost reaches this many USD. Only models with a price count; cooperative, like `--max-campaign-tokens` |
| `--dry-run` | No | `false` | Load the adapter, discover capabilities and count the attack vectors without running them |
| `--defence-profile` | No | — | YAML file declaring the target's active defences; the report gains a "Declared Defences" section and an evasion rate |
| `--incremental` | No | `false` | Reuse cached results for vectors whose inputs are unchanged (`.ziran/scan_cache/`). Opt-in; not for release gates. See [Incremental Scanning](../guides/incremental-scanning.md). |
| `--no-cache` | No | `false` | Bypass the incremental cache: neither read nor write it (overrides `--incremental`) |
| `--carriers` | No | - | YAML file of folders the target's tools read (`workspace_dir`, `knowledge_base_dir`, `page_dir` with `page_url`). Turns on the document and image carrier vectors. A vector whose folder is not named, or whose attachment the adapter cannot send, reads unmeasured, so the scan reports INCOMPLETE. See [Attack Library](attack-library.md#document-and-image-carriers). |
| `--trials` | No | `1` | Run each attack this many times, resetting the target between runs. The vector reads successful when any run succeeds; `evidence.trials` records successes out of the measured runs, `pass_at_k`, `pass_hat_k` (all k runs succeeded) and `flaky` (some measured runs, not all); a run that times out, errors or is skipped by the cost cap is unmeasured. With `--trials` above 1 a phase runs one attack at a time (a reset must not cut another attack's conversation) and its timeout scales by k. SARIF results carry `successes`, `trials`, `measured`, `success_rate` and `flaky`; the Markdown and HTML reports show "Reproduced: 2 of 3, flaky". With `--incremental` each run is cached on its own. Each run costs the target and judge calls of one scan. |
| `--aibom` | No | - | Also write a CycloneDX 1.6 AI-BOM of the target after the results are saved: the model the target config names, the discovered tools, the MCP server or A2A peer, and skill CVE matches (see [AI-BOM](../guides/aibom.md#scan-targets)). Not written with `--dry-run`. A missing or read-only folder exits `2` before the scan starts. |
| `--hybrid-route-share` | No | `0.0` | Share of uncertain traces the hybrid sends to its model judge, `0.0` to `1.0`. `0.0` is deterministic mode, no model call. ziran sends no hybrid call in this release, so a share above `0.0` exits `2`. The flag overrides `hybrid_route_share` in `.ziran/detectors.yaml`; with no LLM backbone the file value is ignored with a warning. |

\* Either `--framework` + `--agent-path` (local) or `--target` (remote) is required.

**Blast radius.** Each dangerous chain gets a blast radius: what its last tool reaches, and
what the source tools of every chain ending at that tool reach, so data a source tool holds
shows on the chain. It is split into demonstrated (the campaign's tool calls touched it) and
reachable (the graph reaches it, no call touched it). The JSON result keeps one radius per last tool in `blast_radius`; the Markdown
and HTML reports show a "Blast radius" section, and each chain's SARIF result carries
`properties.blast_radius`: `demonstrated` and `reachable` (each a map of kind to count),
`external` (true or false) and `data_classes` (a sorted list). To say what a tool or data
source holds, tag it in `.ziran/detectors.yaml`; the key is the node id or the tool name, and the
id wins when both are given. A tag no chain's radius reaches, such as a mistyped id or a tool in
no chain, is named in one warning in the result's `warnings` and the reports. `external`
corrects whether a tool reaches parties outside the organisation:

```yaml
blast_radius:
  tags:
    read_file: {data_class: pii, records: 1200, owner: crm-team}  # secret, pii, financial, source_code
  external:
    upload_report: true
```

Tags are reported exactly as given; without tags the radius lists nodes only. A flat scan links
every dangerous tool to one shared `sensitive_data` node, so tag the tool rather than that node.
When the file is invalid and no LLM backbone is configured, a warning goes to stderr and the
radius has no tags; with an LLM backbone, an invalid file stops the scan, as for every section.

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

# Local iteration: reuse results for unchanged vectors
ziran scan --framework langchain --agent-path agent.py --incremental
```

---

### `ziran cache clear`

Delete every cached result of `ziran scan --incremental` under `.ziran/scan_cache/`.

```
ziran cache clear
```

Prints `Removed <n> cached result(s) from .ziran/scan_cache`. See
[Incremental Scanning](../guides/incremental-scanning.md).

---

### `ziran multi-agent-scan`

Scan a multi-agent system: discover the topology, test each agent, then run cross-agent attacks.
See [Multi-Agent Coordination](../concepts/multi-agent.md).

```
ziran multi-agent-scan --targets FILE [--targets FILE ...] [OPTIONS]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--targets`, `-t` | Yes | — | YAML target config of one agent. Repeat it once per agent |
| `--entry-point` | No | first target | ID of the entry-point agent |
| `--coverage` | No | — | Coverage level: `essential`, `standard`, `comprehensive` |
| `--concurrency` | No | — | Max concurrent attacks per phase |
| `--skip-individual` | No | `false` | Skip the individual agent scans and run only the cross-agent tests |
| `--trace-hops` | No | `false` | Plant each multi-agent vector at every agent with a hop-tagged canary, one request per vector per agent, to show how far an injection spreads ([Hop tracing](../concepts/multi-agent.md#stage-4-hop-tracing)) |
| `--output`, `-o` | No | — | Output directory |

**Examples:**

```bash
# Scan a supervisor and its workers
ziran multi-agent-scan -t supervisor.yaml -t worker.yaml

# Name the entry point, skip the individual scans, trace hops
ziran multi-agent-scan -t router.yaml -t agent_a.yaml -t agent_b.yaml \
  --entry-point router --skip-individual --trace-hops
```

---

### `ziran discover`

Discover agent capabilities without running attacks (Phase 1 only).

```
ziran discover [OPTIONS] [AGENT_PATH]
```

| Option | Description |
|--------|-------------|
| `--framework` | Agent framework: `langchain`, `langgraph`, `crewai`, `bedrock`, `agentcore`, `anthropic`, `openai-agents`, `autogen` |
| `--target` | YAML target config for remote discovery |
| `--protocol` | Protocol override: `rest`, `openai`, `mcp`, `a2a`, `browser`, `auto` |

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
| `--atlas` | Filter by MITRE ATLAS technique id (for example `AML.T0051`) |
| `--custom-attacks` | Include custom YAML vectors |

**Examples:**

```bash
ziran library --list
ziran library --category prompt_injection
ziran library --owasp LLM01
ziran library --atlas AML.T0051
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
| `--output`, `-o` | `<result dir>/pocs` | Output directory |
| `--format` | `all` | PoC format: `python`, `curl`, `markdown`, `all` |
| `--target` | none | Target YAML the scan used. With an `openai` or `rest` protocol, the PoCs send that protocol's request (`openai`: `POST {url}/v1/chat/completions`; `rest`: the configured method, path and body). |
| `--protocol` | none | Override the target's protocol, as in `scan` (used with `--target`). |

`poc` reads the protocol from the YAML only. A config that says `auto` (the default) is not resolved here, so it falls back to the forms below unless you pass `--protocol`. `ziran scan --target` uses the protocol it detected.

With an `openai` or `rest` target:

- The Python PoC is a standalone script that needs only `httpx`.
- The cURL PoC sends the same request. `scan --target` writes it beside the Python PoC.
- Each script takes an optional endpoint as its first argument. It checks the whole reply, tool-call arguments included, for the canaries the scan recorded (a token holding `canary` and a digit, such as `ZX-CANARY-7731`, in the recorded reply or tool-call arguments) and for the matched indicators found there. A token the attack prompt itself sent, and a host or file name such as `canary1.example`, is not a canary. A fixed agent restarted with a fresh canary reads not reproduced.
- A match shows that the reply carries a recorded canary or indicator, so the agent attempted to send it. A fix at the egress tool is not visible to the PoC: an agent fixed only there, with the same canary, still reads reproduced.
- Exit codes: `0` reproduced, `1` not reproduced, `2` the finding has no text indicator to check, `3` (Python PoC only) the reply is JSON nested too deep to parse, so it could not be read. A tool call alone does not count as reproduced.
- Auth headers are not written into the scripts, so add them by hand.

With no target, or another protocol (`mcp`, `a2a`, `browser`, unresolved `auto`):

- The Python PoC defines `reproduce(adapter)`. Run it with `asyncio.run(reproduce(adapter))` and a configured ZIRAN adapter, as before.
- `--format curl` posts `{"message": ...}` to the target URL, or to `http://localhost:8000/invoke` with no target. `scan` writes no cURL PoC for these targets.

**Examples:**

```bash
ziran poc results.json --format python --output ./pocs/
ziran poc results.json --format curl --target target.yaml --protocol openai
bash pocs/poc_<vector>_<campaign>.sh https://agent.example.com/v1/chat/completions
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
| `--baseline FILE` | Fail when a Claude Code agent's tools or chains widen beyond this baseline (see [Allowlist baseline](#allowlist-baseline)) |
| `--write-baseline FILE` | Record each Claude Code agent's tools and chains as the accepted baseline, then report as if `--baseline FILE` was given |
| `--sarif FILE` | Also write the reported findings (after the baseline step and `--severity`) as SARIF v2.1.0 for GitHub code scanning; `json` stdout is unchanged, `SARIF written to FILE` goes to stderr. An unwritable `FILE` exits `2` |
| `--typed-chains` | Also report typed chains: a tool whose name reads data, paired with a tool whose name sends, runs or changes something. A tool is typed by the first read or write verb of its own name (the part after `mcp__<server>__`); a name with no listed verb counts as one that acts. Off by default; not allowed with `--baseline` or `--write-baseline`, since a baseline holds no typed chains. Reads no config file |
| `--aibom FILE` | Also write a CycloneDX 1.6 AI-BOM of the Claude Code plugin: agents, skills with their allowed tools, the models agents name, MCP servers with command and version, and skill CVE matches (see [AI-BOM](../guides/aibom.md)). Exits `2` when PATH holds no Claude Code plugin or agent |

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
| `2` | Usage error (for example `PATH` does not exist, an invalid option, or an unwritable `--sarif FILE`) |

Text mode (the default) keeps its existing behaviour and exits `1` only on `critical`
findings, even when `--severity` is lower.

#### Claude Code plugins

`ziran audit` also audits Claude Code subagent definitions, without running them. They are
detected when `PATH` is:

- a plugin root (`.claude-plugin/plugin.json`, `agents/`, and any `agents` paths in the manifest),
- a directory containing `.claude/agents/`,
- a directory named `agents` (e.g. `ziran audit ./agents/`),
- a single agent `.md` file (frontmatter starting with `---`); only the Claude Code checks run on it.

Agent files are the `*.md` files in those directories (not recursive) whose first line is `---`.
In a directory, Python files are still analysed as before and the Claude Code findings are appended.

| Rule | Severity | Finding | Line |
|------|----------|---------|------|
| `CC000` | high | The agent/plugin file could not be parsed | the problem line (or none) |
| `CC002` | low | A skill bundles a script in a language ZIRAN does not analyse ([Agent Skills](#agent-skills)) | none |
| `SA001` | critical | Secret pattern in the system prompt, `description` or `tools` | the matching line |
| `SA003` | high | A declared tool is dangerous (e.g. `Bash`, `WebFetch`, `Write`) | `tools:` line |
| `SA004` | medium | A declared tool is a wildcard (`Bash(*)`, `mcp__server`, `mcp__server__*`) | `tools:` line |
| `SA007` | high | No `tools` key, or `tools: "*"`: the agent inherits every tool. It is the agent's one tool finding: an inherited set gives no `CC001` or `LT001` row, because it depends on the parent session | `tools:` line (`1` when absent) |
| `CC001` | the chain's risk | A dangerous tool chain over the agent's declared tools (e.g. `Read -> WebFetch`) | `tools:` line |
| `LT001` | critical | The lethal trifecta: the agent's declared tools read private data, see untrusted content and can send data out (e.g. `Read, WebFetch`) | `tools:` line |

The `tools` value is read as the format writes it: a list split at commas or spaces, the `allowed-tools` key when there is no `tools` key, and an empty value (`tools:`, `tools: []`) as an agent with no tool, which gets no `SA007`. `WebFetch` limited to named domains (`WebFetch(domain:docs.example.org)`) is in no chain; `Bash(git status:*)` stays a sink, since a named command can still send data.

When Claude Code definitions are detected, every JSON row (Python rows included) gains two keys:
`agent` (the agent name, `null` for Python rows and `CC000`) and `tools` (the tool strings, in
chain order for `CC001`, the first tool of each leg for `LT001`; `[]` when not applicable).
Otherwise rows keep exactly the five keys above. Each `CC001` row is unique per `(agent, tools)`,
and an agent has at most one `LT001` row.

```json
{
  "rule": "CC001",
  "severity": "critical",
  "file": "my-plugin/agents/researcher.md",
  "line": 4,
  "message": "Agent 'researcher': data_exfiltration via Read -> WebFetch",
  "agent": "researcher",
  "tools": ["Read", "WebFetch"]
}
```

Exit codes are unchanged and apply to the merged report.

##### Agent Skills

`ziran audit` also reads Agent Skills: a folder with a `SKILL.md` whose first line is `---`. It
finds them under `skills/` and `.claude/skills/` of `PATH`, in the manifest's `skills` paths, in
`PATH` itself when it is a skill folder or a folder named `skills`, and in a `SKILL.md` given as
`PATH`. A skill is audited as a skill, not as a subagent:

- Its tools are its `allowed-tools` pre-approvals. A skill without the key grants nothing, so it
  gets no `SA007`, `CC001` or `LT001` row. `allowed-tools: "*"` alone keeps `SA007`. Granted
  tools go through `SA003`, `SA004`, `CC001` and `LT001` as for an agent; messages start with
  `Skill '<name>'` (the `name` key, or the folder name).
- Every bundled file is listed, except under the folders the Python checks skip (`.git`,
  `node_modules`, `.venv` and the rest of `skip_directories`). A `.py` file runs through the
  Python checks once: a directory audit's own Python pass skips each file the skill audit
  analysed, and still reads every other `.py` file. A script in another language (by suffix, the
  executable bit or a `#!` first line) gets a `CC002` (low) row: it is bundled and not analysed,
  so the report never reads clean. Other files (notes, templates) give no row.
- Each skill row, bundled-file rows included, has the skill name in `agent` and
  `"atlas": ["AML.T0110"]` (MITRE ATLAS AI Agent Tool Poisoning), in JSON and in SARIF result
  properties. Rows outside skills keep their keys.
- `CC000` covers what cannot be read safely, and the audit goes on: invalid or too deeply nested
  frontmatter (the message starts with `skill '<folder>':`), a file or symlinked folder that
  resolves outside `PATH`, a symlinked folder inside it (not followed), a `.py` file over 1 MiB,
  more than 1000 bundled files (refused files count), folders nested more than 8 levels, a
  file that is not a regular file, or a `.mcp.json` nested too deeply.
- `--baseline` does not cover skills: skill rows are always reported in full. `--aibom`,
  `--baseline` and `--write-baseline` still need a plugin or an agent: skills alone exit `2`.

##### Lethal trifecta (`LT001`)

An agent holds the lethal trifecta when its tools cover three legs: **private data**, **untrusted
content** and **egress**. A prompt injection in the untrusted content can then make it send the
private data out, whatever order the tools run in. One tool can hold several legs. The legs come
from the tool's name (after the [Claude Code alias map](../concepts/tool-chains.md#claude-code-tool-names)):

| Leg | A tool holds it when its name has |
|-----|-----------------------------------|
| `private_data` | a secret word (`secret`, `credential`, `password`), or a read word and a data word (`file`, `inbox`, `email`, `message`, `customer`, `user`, `contact`, `account`, `record`, `database`, `sql`, `document`, `drive`, `calendar`, `note`, `ticket`, `order`, `memory`, ...) |
| `untrusted_content` | a web word (`http`, `url`, `web`, `browse`, `scrape`, `crawl`, `download`, `rss`, `feed`), or a read word and an inbound word (`inbox`, `email`, `message`, `comment`, `issue`, `chat`, `review`) |
| `egress` | a send word (`send`, `post`, `publish`, `upload`, `share`, `forward`, `reply`, `notify`, `webhook`, `push`, `export`, `request`, `http`, `curl`, ...), `email` or `message` without a read word, or `fetch` with a page word (`url`, `web`, `page`) |

So `Read` is private data, `WebFetch` untrusted content and egress, `read_inbox` private data and
untrusted content, and `send_email` egress. `Bash` holds no leg here: an unscoped `Bash` is
already reported on its own. `ziran scan` runs the same check: one `lethal_trifecta` chain per
agent (a flat agent is all its tools; a graph-shaped agent is each agent node's tools), and the
scan's SARIF from `ziran ci` carries the same `LT001` rule id. On a graph-shaped agent, an agent
that covers the three legs only together with the agents it delegates to (along delegation
edges, transitively) gets a `lethal_trifecta_delegated` chain; its evidence names the agents
(`agent`, `agents`), and the scan's SARIF carries it under rule `LT002`.

`ziran analyze-traces` adds the order: a session gets a `lethal_trifecta` (with `rule_id`
`LT001` in its evidence) only when its calls cover the three legs and an egress call comes after
an untrusted content call. A session that sends before it reads anything untrusted gets none,
and so does one `WebFetch` call on its own: its request leaves before the content arrives.

To correct a tool's legs, list them under `trifecta_roles` in `.ziran/detectors.yaml`. The key is
the tool id or its name; the list replaces the name rules for that tool, and `[]` gives it no leg:

```yaml
trifecta_roles:
  send_email: []                 # only sends to fixed internal addresses
  lookup_order: [private_data]
```

`ziran audit` and `ziran scan` read the file from the working directory. When it is invalid or
unreadable, a warning goes to stderr and the name rules apply to every tool. A `trifecta_roles`
entry can turn `LT001` off for a tool, so review a change to it like a change to the baseline.

Upgrading to the release that adds `LT001` gives a `BL003` row for every agent that holds the
trifecta against an older baseline: review it and record the baseline again with
`--write-baseline`.

#### Allowlist baseline

A baseline records what each Claude Code agent is allowed to have today, so CI fails only when an
agent's tools widen. The loop:

```bash
ziran audit agents/ --write-baseline agents/ziran-baseline.json   # record
git add agents/ziran-baseline.json && git commit -m "chore: record agent baseline"
ziran audit agents/ --baseline agents/ziran-baseline.json          # check (in CI)
# after a reviewed change to an agent's tools: record again and commit
```

`--baseline` and `--write-baseline` are mutually exclusive. `--write-baseline` writes the file and
then reports as if `--baseline` pointed at it (so it exits `0` unless there is another critical
finding, such as a parse issue). The line `Baseline written to FILE (N agents)` goes to stderr.

The file (version `1`) holds, per agent name, the declared `tools` (`null` when the agent has no
`tools` key) and every dangerous chain found over them. Agents are sorted by name and chains by
`tools`, so recording the same agents twice gives identical bytes. It never contains prompts,
descriptions, hook commands or MCP config.

```json
{
  "version": 1,
  "agents": {
    "generalist": {
      "tools": null,
      "chains": [
        {"tools": ["Bash"], "vulnerability_type": "unrestricted_execution", "severity": "high"}
      ]
    },
    "researcher": {
      "tools": ["Read", "Grep", "WebFetch", "mcp__slack__send_message"],
      "chains": [
        {"tools": ["Read", "WebFetch"], "vulnerability_type": "data_exfiltration", "severity": "critical"}
      ]
    }
  }
}
```

Comparison uses agent names, `tools`, and each chain's `tools` and `vulnerability_type`,
verbatim and case-sensitive (`severity` is for reviewers), so a recorded `data_exfiltration` chain
over `Read, WebFetch` does not accept a `lethal_trifecta` over the same tools. Scoping `Bash` to `Bash(npm test:*)` is
therefore reported as a new tool.

With a baseline, recorded grants are accepted: `CC001` and `LT001` rows for recorded chains and `SA003` /
`SA004` / `SA007` rows for recorded grants are dropped. `SA001` secrets and Python findings are
never accepted, and `CC000` parse issues become `critical`, so a broken agent file cannot pass as
a removed agent. Each widening is appended as a `critical` row:

| Rule | Widening | `tools` | Message |
|------|----------|---------|---------|
| `BL001` | a restricted agent gains a tool | `[tool]` | `Agent '<name>' gains tool '<tool>' not in the baseline` |
| `BL002` | a restricted agent loses its `tools` key | `[]` | `Agent '<name>' lost its 'tools' key and now inherits every tool` |
| `BL003` | a dangerous chain not in the baseline | chain tools | `Agent '<name>': new <risk> chain <type> via <A -> B> not in the baseline` |
| `BL004` | an agent not in the baseline | its tools | `Agent '<name>' is not in the baseline` |

Rows use the same seven keys as other Claude Code rows, on the agent's `tools:` line. Narrowings
(a tool, chain, `tools` key restriction or agent removed) never fail. In JSON, whenever either flag
is given, the document gains a `baseline` key (without the flags there is none):

```json
{
  "files_analyzed": 5,
  "findings": [],
  "baseline": {
    "narrowed": [{"agent": "researcher", "change": "tool_removed", "tools": ["WebFetch"]}]
  }
}
```

`change` is one of `tool_removed`, `tools_key_added`, `chain_removed` or `agent_removed`. Text
mode prints a "Baseline narrowed" panel. A narrowed baseline is not rewritten: record it again, or
a removed tool can come back without failing.

Exit codes follow the rules above, applied after the baseline step. Every `BL00x` row is
`critical`, so any widening exits `1` under every `--severity`; narrowings never change the exit
code. Exit `2` also covers: both flags given, a baseline file that is missing, unreadable, not
JSON or not matching the format (the error names the key path, never the value), a write failure,
and either flag on a `PATH` without Claude Code agent definitions.

Upgrading ZIRAN can add chain patterns and so new `BL003` rows for unchanged agents; record the
baseline again when you bump the pinned release. Proposing a narrower allowlist is not provided.

---

### `ziran export-policy`

Export proven findings as runtime guardrail policies or Sigma detection rules.

```
ziran export-policy --result FILE --format FORMAT [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--result` | — (required) | Campaign result JSON |
| `--format` | — (required) | `rego` (OPA), `cedar`, `nemo`, `invariant` or `sigma` |
| `--out` | `policies` | Output directory |
| `--severity-floor` | `medium` | Lowest severity to include: `critical`, `high`, `medium`, `low` |
| `--exclude-probes` | off | `sigma` only: leave out spans in this scan's probe trace ids (`probe_markers`, see [Remote Agents](../guides/remote-agents.md#probe-markers)) |
| `--verbose` | off | Print the reason a chain is skipped |

```bash
ziran export-policy --result reports/campaign_report.json --format rego --out policies/
ziran export-policy --result reports/campaign_report.json --format sigma --out rules/ --exclude-probes
```

See [Sigma Detection Rules](../guides/detection-rules.md) and
[Policy Refresh Automation](../guides/policy-refresh-automation.md).

---

### `ziran analyze-traces`

Match production traces against dangerous tool chains.

```
ziran analyze-traces --source otel|langfuse [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--source` | `otel` or `langfuse` (required) |
| `--input` | Trace file: JSONL for OTel, JSON for Langfuse. Without it, `langfuse` pulls from the API |
| `--project-id`, `--session-id`, `--since`, `--incremental` | Langfuse API pull: keep one project, pull one session, set a time window (`24h`, `7d`, an ISO date), start where the last pull ended |
| `--out`, `--format` | Report directory and format: `json`, `markdown`, `html` |
| `--alert`, `--config`, `--digest`, `--dry-run-alerts` | Deliver matches to the sinks in the `alerts:` block of `--config`; one digest issue instead of one per session; preview without sending |
| `--predeploy-result` | Pre-deploy campaign result JSON to correlate matches against |
| `--aibom FILE` | AI-BOM from `ziran audit --aibom`: MCP servers and agents the traces name but the BOM lacks are added as shadow, and the result goes to `aibom.json` in `--out` |
| `--verbose`, `-v` | Verbose output |

Exit `0` when no critical chain matched, `1` when one did, `2` when the command could not
finish. See [Analyze Traces](../guides/analyze-traces.md).

---

### `ziran mcp-hostile-server`

Act as a hostile MCP server over stdio and score how the host's client replies to sampling,
elicitation and roots requests. Needs `ziran[mcp]`.

```
ziran mcp-hostile-server --record-dir DIR [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--record-dir` | — (required) | Folder for the record and the `CampaignResult` JSON |
| `--vector` | all | Server-surface vector id to send. Repeatable |
| `--family` | — | Sub-family to send: `sampling-injection`, `elicitation-phishing`, `elicitation-overbroad`, `roots-capability-creep`. Repeatable; adds to `--vector` |
| `--timeout` | `120` | Seconds to wait for each client reply (at least 1) |
| `--fault` | — | Fault the `--fault-tools` return: `error`, `timeout` (hangs 300 s, then errors), `oversize` (1 MB), `malformed` (broken JSON) or `slow` (5 s) |
| `--fault-tools` | — | Comma-separated tool names the server offers, each returning `--fault` (at most 20) |

See [Hostile MCP Server](../guides/mcp-hostile-server.md).

---

### `ziran pentest`

Run an autonomous, LLM-driven pentesting agent against a target. Needs `ziran[pentest]`.

```
ziran pentest --goal TEXT --llm-provider NAME --llm-model NAME (--target FILE | --framework NAME) [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--goal`, `-g` | — (required) | The objective, for example `Find prompt injection vulnerabilities` |
| `--llm-provider`, `--llm-model` | — (required) | The agent's reasoning model |
| `--target` | — | YAML target config for a remote agent |
| `--framework` | — | In-process framework: `langchain`, `crewai`, `bedrock`, `agentcore`, `anthropic` |
| `--interactive`, `-i` | off | Red-team REPL |
| `--max-iterations` | `10` | Maximum agent iterations |
| `--embedding-model` | — | Embedding model for finding deduplication |
| `--llm-rpm`, `--llm-tpm`, `--llm-max-retries` | — | Client-side rate limits and retries, as for `scan` |
| `--output`, `-o` | — | Output directory |

See [Pentesting Agent](../concepts/pentesting-agent.md).

---

### `ziran init`

Write a starter `ziran.yaml` in the current directory. `--non-interactive` skips the prompts and
uses the defaults, for scripts and CI.

---

### `ziran validate`

```
ziran validate TARGET_CONFIG [--protocol rest|openai|mcp|a2a|browser|auto]
```

Check that a target YAML is well formed, its URL is reachable, its auth tokens resolve and its
protocol can be detected.

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
| `--aibom FILE` | none | AI-BOM from `ziran audit --aibom`. MCP servers and agents the traces name but the BOM lacks are added as shadow; the result goes to `aibom.json` in `--out` |
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
`tool_poisoning` findings (severity `critical`, `high`, `medium` or `low`). Later runs diff against
the baseline. A redirect whose `call <tool> instead` target is exactly the name of another tool on
the same server is reported as `sibling_redirect` at `medium`; it stays a `critical`
`tool_redirect` if the same text also carries an exfiltration or authority pattern, or names any
tool outside the server. `always` / `never` / `silently` describing the tool's own output
("never returns an empty list") are reported at `low`; model-directed imperatives (`you must`,
`before calling`, `ignore previous`, `do not tell`, `always call`, ...) stay `high`.
`tool_poisoning` findings are emitted only on first registration, when no snapshot exists, so
`previous_value` is always `null`: they are first-measurement information, not drift. Exit codes
count only `high`/`critical`, so a server whose only findings are sibling redirects and
output-contract imperatives exits `0`.

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

`RESULT_FILE` is a campaign result JSON or the SARIF ziran wrote from one (`--sarif`); both gate
alike. A SARIF without ziran's run properties exits 1 and names them; `--sarif` and `--policy` are
skipped for a SARIF input. See
[Gate a scan's SARIF](../guides/cicd-integration.md#gate-a-scans-sarif).

| Option | Default | Description |
|--------|---------|-------------|
| `--gate-config`, `-g` | — | Quality gate YAML config |
| `--policy`, `-p` | — | Policy file for rule evaluation |
| `--sarif` | — | Write SARIF v2.1.0 report to path |
| `--suppressions` | `.ziran/suppressions.yaml` if present | Accepted-findings file; see [CI/CD guide](../guides/cicd-integration.md#suppressing-accepted-findings) |
| `--github-annotations` | `true` | Emit GitHub Actions annotations |
| `--github-summary` | `true` | Write GitHub Actions step summary |

With `fail_on_goal_met: true` in the gate config, the gate fails when a vector's side-effect goal was
met (rule `goal_met`, naming the vector and the tool-call evidence). This works on a result JSON and
on a SARIF written by this release, which carries each goal's state. See
[Quality Gate](../guides/cicd-integration.md#quality-gate).

**Examples:**

```bash
# Simple gate check
ziran ci results.json --gate-config gate.yaml

# Gate the SARIF a scan wrote
ziran ci results.sarif --gate-config gate.yaml

# Full CI pipeline
ziran ci results.json \
  --gate-config gate.yaml \
  --policy policy.yaml \
  --sarif results.sarif \
  --github-annotations \
  --github-summary
```
