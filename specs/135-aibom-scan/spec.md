# Spec 135: `ziran scan --aibom` and plugin skills in the CycloneDX AI-BOM

**Status**: Active

## Promise (in my words)

`ziran scan --aibom FILE` writes a CycloneDX 1.6 JSON BOM of the scanned target, in the shape `ziran audit --aibom` already writes (spec 123). It lists the target, the model the target config names, the tools discovery found, the MCP server when the target is one, the A2A peer and its skills from the agent card, and the skill CVE database matches on the discovered tools. `ziran audit --aibom` also lists each skill of the plugin as a component with its `allowed-tools`. A plugin's agent, skill and MCP server refs gain the plugin's name, so two plugins with an agent of one name never share a ref. `analyze-traces --aibom` matches on names, so it reads BOMs with the old refs and the new ones alike.

## Acceptance

- Given a scan target config, when `ziran scan --aibom out.json` runs, then `out.json` validates against CycloneDX 1.6 and lists the target's model, tools and MCP servers.
- Given a plugin with a `skills/` folder, when `ziran audit --aibom` runs, then each skill appears as a component with its allowed-tools.

## Behaviour

- Scan BOM subject (`metadata.component`, `application`, ref `agent:<name>`): the agent card's name, else the target URL's host, else the agent file's stem. Properties: `ziran:source` (the target config or agent file as given), `ziran:protocol` (the resolved protocol, or the framework), `ziran:tool` per discovered capability of type tool, data access or external API, `ziran:skill` per skill capability. Permission capabilities (auth schemes) are not listed.
- Model: `openai.model` of the target config, a `machine-learning-model` component `model:<id>`; else `ziran:model: unknown` on the subject.
- MCP server: when the resolved protocol is `mcp`, a service `mcp:<name>` with the target endpoint and `ziran:version: unknown`.
- A2A peer: when the adapter fetched an agent card, a service `a2a:<card name>` with its version (else `ziran:version: unknown`), endpoints from `supportedInterfaces`, and one `ziran:skill` per card skill id.
- Endpoints in the scan BOM drop userinfo, query and fragment (the spec 123 `_endpoint`). Headers, auth and env values are never read into the BOM.
- CVE matches: `SkillCVEDatabase.check_agent` on the discovered capabilities, `in_triage`, affecting the subject.
- `dependencies`: the subject depends on its model, MCP server and A2A peer.
- `--aibom` is written after the results are saved; `--dry-run` writes none. A missing or read-only folder exits 2 before the adapter loads; a write that still fails is a usage error naming `--aibom`.
- Capabilities with a `probe_` id (guesses from reply text by probe discovery) are not listed.
- Shadow agents: known agent names come from `application` components that are not skills (fix round 1), so a skill or model name never hides a trace agent.
- Audit BOM skills: each skill is an `application` component `skill:<plugin>/<name>` with `ziran:kind: skill`, `ziran:source` and one `ziran:allowed-tool` per pre-approved tool; CVE matches cover its allowed tools. Audit refs: `agent:<plugin>/<name>`, `skill:<plugin>/<name>`, `mcp:<plugin>/<name>` when a manifest names the plugin, else unprefixed. `model:<name>`, `plugin:<name>` and `vuln:<id>` are unchanged.

## Out of scope

Skills in `ziran scan`: no scan target is a Claude Code plugin (`ziran audit` is that path). MCP server versions from `serverInfo`: the handler does not keep it.

## Assumptions

- The ref change is not breaking: spec 123 has not been released (`git merge-base --is-ancestor 2572f26 origin/main` is false). Overturned if a release shipped it first.
- "CVE matches already computed": the scan computes none today, so the BOM runs the same name match the audit runs on the discovered tools. Overturned if the scan gains its own CVE stage.
- The OpenAI preset's default model (`gpt-4`) counts as named by the config: it is the model ZIRAN requests.
- `probe_` ids are guesses, as `agent_scanner/trials.py` already treats them; a declared tool whose own name starts `probe_` would be left out. Overturned if adapters mark probe guesses another way.
- A scan BOM names the target by card name or host, so `analyze-traces` against it can flag the target as shadow (documented); a target `name` is a follow-up.
- The A2A peer is the scanned agent's own card; `lookalike_cards` are registry probes, not peers, and stay out.
