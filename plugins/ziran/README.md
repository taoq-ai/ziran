# ZIRAN plugin for Claude Code

Four skills that drive the [ZIRAN](https://github.com/taoq-ai/ziran) CLI and explain what it
finds. Claude reads the output, explains each attack path, proposes the narrowest tool change and
writes suppressions with a reason a reviewer can check.

| Skill | Use it to |
|---|---|
| `audit-agents` | Audit Claude Code subagents, plugins or agent code with `ziran audit`; SARIF; an allowlist baseline; a GitHub Actions gate. |
| `triage-findings` | Read a scan result, decide fix or accept, write `.ziran/suppressions.yaml`, gate with `ziran ci`, export guardrail policies and PoCs. |
| `set-up-scan` | Discover an agent's tools, write a target config, dry-run, then run a scan with coverage, phases, rate limits and a cost cap. |
| `threat-model-agent` | Map a tool list to dangerous chains and MITRE ATLAS techniques; confirm with `ziran audit` when installed. Works without ZIRAN. |

## Install

```text
/plugin marketplace add taoq-ai/ziran
/plugin install ziran@ziran
```

From a shell: `claude plugin marketplace add taoq-ai/ziran`, then
`claude plugin install ziran@ziran`.

The skills call the `ziran` CLI (`pip install "ziran>=0.42.0"`). `threat-model-agent` works
without it. Only a scan that uses LLM features needs an LLM API key.

## Keeping the skills current

`tests/unit/test_claude_plugin_skills.py` checks every `ziran` command and flag the skills name
against the live CLI, runs the offline commands against the repository's examples, checks the
GitHub Action inputs, and checks that
[the chain to ATLAS table](skills/threat-model-agent/references/atlas-chains.md) covers every
chain type ZIRAN reports. Bump `version` in `.claude-plugin/plugin.json` when a skill changes:
Claude Code updates an installed plugin only when its version changes.
