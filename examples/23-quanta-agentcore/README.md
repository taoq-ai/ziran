# Quanta — AgentCore composition scan

Scan **Quanta**, a *defensibly-architected* Amazon Bedrock AgentCore data-analyst
agent, and find the risk a tool-by-tool review can't: a critical
**data-exfiltration composition**.

> Companion to the talk *"When Your Agent Tools Combine Against You"*.
> Full deployable agent: **https://github.com/taoq-ai/quanta**

## The point

Quanta has four tools, each individually hardened and review-passing:

| Tool | Declared control |
|---|---|
| `search_database` | read-only replica · parameterised queries · row cap |
| `run_analysis` | sandbox · no network · no imports |
| `fetch_reference` | egress allowlist (destination) |
| `send_email_report` | domain allowlist · audit log · dry-run |

Tool by tool, this passes review — 4/4 approved. But an LLM agent can *sequence*
its tools, and ZIRAN's `ToolChainAnalyzer` flags the path no per-tool review
catches:

```
search_database  ──▶  send_email_report     CRITICAL  data_exfiltration
(private data)        (external channel)
```

The verdict is from ZIRAN's **built-in** dangerous-composition patterns — nothing
in this example is hand-labelled as dangerous. The danger lives in the graph.

## What it demonstrates

- Scanning an AgentCore agent in-process via `AgentCoreAdapter`.
- Reporting a declared tool catalogue through a custom `discover_capabilities`.
- Adding the agent's **composition surface** (tool→tool data-flow) to the graph.
- Running `ToolChainAnalyzer` to surface the dangerous combination.
- Rendering the interactive HTML report with the composition highlighted.

## Run

```bash
uv run python main.py
# -> prints the critical chain and writes reports/ (JSON, Markdown, interactive HTML)
```

No AWS or API keys needed — a compact, deterministic stand-in for Quanta is
bundled. To scan the **real** deployed agent, install the
[quanta](https://github.com/taoq-ai/quanta) package and point the adapter at its
`quanta.agent.invoke` entrypoint (see `scripts/scan_quanta.py` in that repo).

## ⚠️ Note

Quanta is a **deliberately composable** educational agent with a known,
intentional vulnerability by design. Do not deploy it for real.
