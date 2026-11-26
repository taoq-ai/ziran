# AI-BOM

`ziran audit --aibom FILE` writes a CycloneDX 1.6 bill of materials of a Claude Code plugin: what
the plugin is made of, read from its files without running anything. `ziran analyze-traces --aibom
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
| Each model a subagent names | `components`, type `machine-learning-model` | the agent's `model` key |
| Each MCP server | `services`, with `ziran:command`, `ziran:transport`, `version` and `endpoints` | `.mcp.json` and the manifest's `mcpServers` |
| Skill CVE matches on a declared tool | `vulnerabilities`, `analysis.state: in_triage` | ZIRAN's skill CVE database |
| Agent to model and agent to MCP server | `dependencies` | the agent's `model` and its `mcp__<server>__*` tools |

Every entry carries a `ziran:source` property: the file it was read from, relative to the audited
path, with the line where the parser keeps one.

ZIRAN does not guess. What it cannot read from the files is marked `unknown`:

- `ziran:version: unknown` on a plugin with no `version`, or on an MCP server whose arguments do not
  pin a package (`pkg@1.2.3` or `pkg==1.2.3`).
- `ziran:model: unknown` on an agent with no `model` key or `model: inherit`: it runs on the
  session's model.
- `ziran:tools: unknown` on an agent with no `tools` key: it inherits every tool of the session.

A CVE match is a match on the tool's name, so it stays in triage until someone confirms it.
Datasets and model weights are out of scope.

## What never reaches the BOM

MCP `args`, `env` and `headers`, and a URL's user, password, query and fragment, can hold secrets,
so the BOM leaves them out. The only argument read is a pinned package, for its name and version.
The plugin's own folder in a command reads `${CLAUDE_PLUGIN_ROOT}`.

## Shadow servers and agents

A trace names an MCP server in a tool id, `mcp__<server>__<tool>`. Claude Code names a plugin's
server `plugin_<plugin>_<server>`, and that form matches the BOM's server too. An agent is the
session's agent name (OTel `service.name`, Langfuse `metadata.agent`); `unknown` is skipped.

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
      "bom-ref": "agent:researcher",
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
      "bom-ref": "mcp:filesystem",
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
      "bom-ref": "mcp:search",
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
    {"ref": "agent:researcher", "dependsOn": ["model:sonnet", "mcp:filesystem"]}
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
      "affects": [{"ref": "agent:researcher"}]
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
