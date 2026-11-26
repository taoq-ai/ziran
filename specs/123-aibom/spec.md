# Spec 123: CycloneDX AI-BOM of a Claude Code plugin, with shadow servers from traces

**Status**: Active

## Promise (in my words)

`ziran audit PATH --aibom FILE` writes a CycloneDX 1.6 JSON BOM of the Claude Code plugin under PATH. It lists the plugin, each subagent with its declared tools, each model a subagent names, each MCP server with its command, transport, version and endpoint, and the skill CVE database matches on the declared tools. Every entry cites the file (and line, when the parser keeps one) it came from. What the files do not say reads `unknown`. `ziran analyze-traces --aibom FILE` reads that BOM and adds each MCP server or agent the traces name but the BOM lacks, flagged `ziran:shadow: true`, to `aibom.json` in `--out`.

## Acceptance

- Given a Claude Code plugin audit, when `--aibom out.json` is set, then the file validates against the CycloneDX 1.6 JSON schema and lists each MCP server with its command and version (`unknown` when no argument pins one).
- Given a trace that names an MCP server missing from the BOM, when traces are analysed with `--aibom`, then that server is listed as shadow.

## Behaviour

- Components: subagents (`application`), named models (`machine-learning-model`, deduplicated by name, one `ziran:source` per agent that names it). The plugin is `metadata.component`. MCP servers are `services` (`bom-ref` `mcp:<name>`; a later duplicate name is skipped). `dependencies` link an agent to its model and to the servers of its `mcp__<server>__*` tools.
- Version of an MCP server: only when a known runner (`npx`, `bunx`, `uvx`, `pipx run`, `pnpm dlx`, `yarn dlx`) starts it and the first argument after the runner's own no-value flags is `pkg@<digit>...` or `pkg==<digit>...`. Any other flag ends the search (it may take a value such as a password); else `ziran:version: unknown`.
- Never in the BOM: MCP `args` (except a pinned package name), `env`, `headers`, URL user, password, query and fragment. The config file's folder in a command reads `${CLAUDE_PLUGIN_ROOT}`. `${VAR}` is never expanded from the auditor's environment (the static loader reads the config as written). Kept as written: the `command` string and the URL path.
- `model` absent, empty or `inherit`: `ziran:model: unknown`. No `tools` key (or `*`): `ziran:tools: unknown`; an empty declared list is known and lists no tool.
- CVE matches: `SkillCVEDatabase.check_agent` per declared tool; one vulnerability per CVE id with every affected agent; `analysis.state: in_triage`.
- Shadow: a trace tool id `mcp__<server>__<tool>` whose server is neither a BOM service name nor `plugin_<plugin>_<name>`; a session `agent_name` other than `unknown` that is not a BOM component or the plugin. Each is added once with the first session as source; the BOM `version` goes up by one when anything is added.
- `--aibom` on a PATH with no Claude Code plugin or agent exits 2. A file that is not a CycloneDX 1.6 JSON BOM, or whose `metadata`, `components`, `services` or `version` has the wrong shape, makes `analyze-traces` exit 2 with a value-free message before any trace is read, report written or alert sent.

## Out of scope

`ziran scan` (target config models, discovered tools, A2A peers), skills (the parser does not read `skills/`), hooks, datasets and weights. Candidates for follow-up items.

## Assumptions

- MCP servers are CycloneDX `services` (stdio or remote), since the BOM names how the agent reaches them, not a shipped artifact. Overturned if a consumer needs them as components.
- Claude Code names a plugin's MCP server `plugin_<plugin>_<server>` in tool ids; both forms count as known. A wrong form would only add a false shadow entry.
- The trace's agent name is the host service name for Claude Code OTel (`claude-code`), so a Claude Code trace adds that host as a shadow agent. Kept: it is the runtime that ran the tools and is not in the plugin's BOM.
- The schema is vendored as a test fixture and validated with `jsonschema` in the test group only; no runtime dependency.
