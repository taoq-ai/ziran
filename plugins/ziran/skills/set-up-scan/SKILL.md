---
name: set-up-scan
description: Set up a first ZIRAN security scan of an AI agent - discover its tools, write and check a target config, dry-run the attack plan, then run a scan with a coverage level, phases, LLM rate limits and a cost cap. Use when the user wants to scan or pentest their agent with ZIRAN, connect ZIRAN to a local framework agent or a remote HTTP, OpenAI-compatible, MCP or A2A endpoint, or keep a scan within a token or dollar budget.
---

# Set up a ZIRAN scan

A scan sends attack prompts to a live agent and checks what it does, including which tools it
calls. Your job: pick the right mode, get a configuration that loads before anything is sent,
and keep the first run small and within budget.

Needs `ziran>=0.42.0` (`ziran --version`); framework agents need the extra, e.g.
`pip install "ziran[langchain]"`. Only scan an agent the user owns or is authorised to test.

## 1. Choose the mode

- **In-process**: the agent is Python code in a supported framework (`langchain`, `langgraph`,
  `crewai`, `bedrock`, `agentcore`, `anthropic`). Use `--framework` with `--agent-path`.
- **Remote**: the agent is a running endpoint. Write a target YAML and use `--target`.

If the user only has agent definitions and no running agent, a scan is the wrong tool: use the
`audit-agents` skill.

## 2. Discover capabilities (no attack prompts)

```bash
ziran discover --framework langchain ./my_agent.py
ziran discover --target target.yaml
```

Summarise the tools found and which pairs form chains (see
[atlas-chains.md](../threat-model-agent/references/atlas-chains.md)); they decide which phases
matter.

## 3. Configuration

`ziran init --non-interactive` writes a starter `ziran.yaml` that records the choices. `ziran
scan` does not read it, so pass the settings as flags.

For a remote agent, write the target YAML:

```yaml
name: my-agent
url: https://agent.example.com
protocol: openai          # rest | openai | mcp | a2a | browser | auto
auth:
  type: bearer
  env_var: AGENT_TOKEN    # read from the environment; never write the token in the file
tls:
  verify: true
timeout: 30
```

`ziran validate target.yaml` checks the file, that the URL answers, that auth resolves and that
the protocol can be detected; it needs the endpoint up. Add `--protocol openai` to force a
protocol.

## 4. Dry run

```bash
ziran scan --target target.yaml --dry-run
```

This loads the adapter, discovers capabilities and counts vectors and prompts without sending an
attack. Fix any error before step 5. Report the vector and prompt counts to the user.

## 5. First scan: small and capped

```bash
ziran scan --target target.yaml --coverage essential --phases reconnaissance --phases vulnerability_discovery -o ziran_results
```

- `--coverage`: `essential` (critical only), `standard` (critical and high, the default),
  `comprehensive` (all). Start with `essential`.
- `--phases`: run fewer phases first. Repeat the flag for each phase (`--phases a b` is an
  error); the full list is in `ziran scan --help`.
- LLM-backed features (`--llm-provider`, `--llm-model`, for the judge and adaptive strategy)
  spend tokens. Cap them: `--max-cost 5` stops scheduling new attacks at an estimated 5 USD,
  `--max-campaign-tokens 200000` at a token count. Both are cooperative: running attacks finish.
- Rate limits for the LLM provider: `--llm-rpm 30 --llm-tpm 60000`.
- In-process instead of remote: `ziran scan --framework langchain --agent-path ./my_agent.py --coverage essential`.
- `--resume` continues an interrupted scan from the `-o` directory.

## 6. Next

The result is `ziran_results/campaign_<id>_report.json`. Hand it to the `triage-findings` skill:
read the findings, fix or accept, then gate CI with `ziran ci`.
