# AI-BOM

`ziran audit --aibom FILE` writes a CycloneDX 1.6 bill of materials of a Claude Code plugin: what
the plugin is made of, read from its files without running anything. `ziran scan --aibom FILE`
writes the same shape for a scanned target (see [Scan targets](#scan-targets)). `ziran analyze-traces --aibom
FILE` then compares production traces with that BOM and adds every MCP server or agent the traces
name but the BOM lacks, flagged as shadow.

```bash
ziran audit ./my-plugin/ --aibom aibom.json
ziran analyze-traces --source otel --input traces.jsonl --out ./reports --aibom aibom.json
# ./reports/aibom.json: the BOM plus the shadow entries
```

The audit's findings, exit code and `--format json` output are unchanged; `AI-BOM written to FILE`
goes to stderr. A PATH with no Claude Code plugin or agent exits `2`.

## What the BOM lists

| Entry | CycloneDX | From |
|-------|-----------|------|
| The plugin | `metadata.component`, type `application` | `.claude-plugin/plugin.json` |
| Each subagent | `components`, type `application`, one `ziran:tool` property per declared tool | `agents/*.md` |
| Each skill | `components`, type `application`, `ziran:kind: skill`, one `ziran:allowed-tool` property per pre-approved tool | `skills/*/SKILL.md` |
| Each model a subagent names | `components`, type `machine-learning-model` | the agent's `model` key |
| Each MCP server | `services`, with `ziran:command`, `ziran:transport`, `version` and `endpoints` | `.mcp.json` and the manifest's `mcpServers` |
| Skill CVE matches on a declared tool | `vulnerabilities`, `analysis.state: in_triage` | ZIRAN's skill CVE database |
| Agent to model, agent or skill to MCP server | `dependencies` | the agent's `model` and its `mcp__<server>__*` tools |

Refs name the plugin when its manifest does: `agent:<plugin>/<name>`, `skill:<plugin>/<name>` and
`mcp:<plugin>/<name>`, so two plugins with an agent of one name never share a ref. Without a
manifest the refs are `agent:<name>` and so on. `model:<name>`, `plugin:<name>` and `vuln:<id>`
carry no prefix.

Every entry carries a `ziran:source` property: the file it was read from, relative to the audited
path, with the line where the parser keeps one.

ZIRAN does not guess. What it cannot read from the files is marked `unknown`:

- `ziran:version: unknown` on a plugin with no `version`, or on an MCP server that a known runner
  (`npx`, `bunx`, `uvx`, `pipx run`, `pnpm dlx`, `yarn dlx`) does not start with a pinned package
  (`pkg@1.2.3` or `pkg==1.2.3`).
- `ziran:model: unknown` on an agent with no `model` key or `model: inherit`: it runs on the
  session's model.
- `ziran:tools: unknown` on an agent with no `tools` key: it inherits every tool of the session.

A CVE match is a match on the tool's name, so it stays in triage until someone confirms it.
Datasets and model weights are out of scope.

## What never reaches the BOM

MCP `args`, `env` and `headers`, and a URL's user, password, query and fragment, can hold secrets,
so the BOM leaves them out. The only argument read is the package a known runner starts, for its
name and version; ZIRAN stops at the first runner flag it does not know, since that flag may take a
value such as a password. `${VAR}` placeholders are written as they are, never expanded from your
environment. The plugin's own folder in a command reads `${CLAUDE_PLUGIN_ROOT}`.

Two things are kept as the config writes them: the `command` (the whole string, so a command line
with a token in it shows that token) and the URL path (so a key in the path, as in
`https://host/mcp/<key>`, shows too). Put secrets in `env`, `headers` or a placeholder instead.

## Scan targets

`ziran scan --aibom FILE` writes the BOM after the scan's results are saved; `--dry-run` writes
none. A `FILE` whose folder is missing or not writable exits `2` before the scan starts.

| Entry | CycloneDX | From |
|-------|-----------|------|
| The target | `metadata.component`, type `application`, `agent:<name>`, with `ziran:protocol`, one `ziran:tool` per discovered tool and one `ziran:skill` per discovered skill | the config `name`, else the agent card's name, else the MCP `serverInfo.name`, else the URL's `host:port`, else the agent file's name |
| The model | `components`, type `machine-learning-model` | `openai.model` in the target config; else `ziran:model: unknown` |
| The MCP server | `services`, `mcp:<name>`, with its endpoint and `ziran:version: unknown` | a target on the `mcp` protocol |
| The A2A peer | `services`, `a2a:<name>`, with its version, endpoints and one `ziran:skill` per card skill | the target's agent card |
| Skill CVE matches on a discovered tool | `vulnerabilities`, `analysis.state: in_triage` | ZIRAN's skill CVE database |

Auth schemes are not listed, nor are tools that probe discovery guessed from the target's replies
(ids starting `probe_`). The BOM never holds the target's headers, auth or environment values,
and its endpoints drop the user, password, query and fragment, as for MCP servers.

A scan BOM names the target, and its MCP server, in this order: the target config's `name`, the
agent card's name, the MCP server's `serverInfo.name`, the URL's `host:port` (just `host` when the
URL has no port), the agent file's name. Set `name` (free text; the ref uses a lowercase slug of it, so `My Agent` gives `my-agent`)
to the key your client uses for the server (`mcp__<key>__<tool>`) and the service name your traces
carry, and `analyze-traces --aibom` will not list the scanned target as a shadow server or agent.
Two MCP targets on one host with different ports get distinct refs.

## Shadow servers and agents

A trace names an MCP server in a tool id, `mcp__<server>__<tool>`. Claude Code names a plugin's
server `plugin_<plugin>_<server>`, and that form matches the BOM's server too. An agent is the
session's agent name (OTel `service.name`, Langfuse `metadata.agent`); `unknown` is skipped.

Matching reads names, never refs, so a BOM written before refs named the plugin still matches.
An agent is known when an `application` component other than a skill bears its name: a trace
agent named like a skill or a model is still shadow.
Each one the BOM lacks is added once, with `ziran:shadow: true` and a `ziran:source` naming the
first session that used it. The BOM's `version` goes up by one when anything is added.

## Example

The `.mcp.json` of a plugin `aibom-plugin` version 1.4.0:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", "/srv/docs"]
    },
    "search": {"type": "http", "url": "https://user:secret@mcp.example.com/mcp?key=abc"}
  }
}
```

Its agent `agents/researcher.md` names `model: sonnet` and the tools `Read, WebFetch,
mcp__filesystem__read_file`. Part of the BOM (`serialNumber`, `metadata` and the rest trimmed):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "machine-learning-model",
      "bom-ref": "model:sonnet",
      "name": "sonnet",
      "properties": [{"name": "ziran:source", "value": "agents/researcher.md:4"}]
    },
    {
      "type": "application",
      "bom-ref": "agent:aibom-plugin/researcher",
      "name": "researcher",
      "properties": [
        {"name": "ziran:source", "value": "agents/researcher.md:2"},
        {"name": "ziran:tool", "value": "Read"},
        {"name": "ziran:tool", "value": "WebFetch"},
        {"name": "ziran:tool", "value": "mcp__filesystem__read_file"}
      ]
    }
  ],
  "services": [
    {
      "bom-ref": "mcp:aibom-plugin/filesystem",
      "name": "filesystem",
      "version": "2025.7.1",
      "properties": [
        {"name": "ziran:source", "value": ".mcp.json"},
        {"name": "ziran:transport", "value": "stdio"},
        {"name": "ziran:command", "value": "npx"},
        {"name": "ziran:package", "value": "@modelcontextprotocol/server-filesystem"}
      ]
    },
    {
      "bom-ref": "mcp:aibom-plugin/search",
      "name": "search",
      "endpoints": ["https://mcp.example.com/mcp"],
      "properties": [
        {"name": "ziran:source", "value": ".mcp.json"},
        {"name": "ziran:transport", "value": "streamable-http"},
        {"name": "ziran:version", "value": "unknown"}
      ]
    }
  ],
  "dependencies": [
    {"ref": "agent:aibom-plugin/researcher", "dependsOn": ["model:sonnet", "mcp:aibom-plugin/filesystem"]}
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln:CVE-2025-53109",
      "id": "CVE-2025-53109",
      "source": {"name": "ZIRAN skill CVE database"},
      "ratings": [{"severity": "high"}],
      "analysis": {
        "state": "in_triage",
        "detail": "Tool name matches the database entry; not confirmed."
      },
      "affects": [{"ref": "agent:aibom-plugin/researcher"}]
    }
  ]
}
```

A trace that calls `mcp__slack__post_message` then adds, in `./reports/aibom.json`:

```json
{
  "bom-ref": "shadow-mcp:slack",
  "name": "slack",
  "properties": [
    {"name": "ziran:shadow", "value": "true"},
    {"name": "ziran:source", "value": "trace otel session cc-1"}
  ]
}
```

The tests validate the BOM against the official CycloneDX 1.6 JSON schema, kept under
`tests/fixtures/cyclonedx/`.
