# ZIRAN — AI Agent Security Testing

**Find vulnerabilities in AI agents — not just LLMs, but agents with tools, memory, and multi-step reasoning.**

---

## The Problem

Traditional security tools test the **LLM** (prompt injection, jailbreaks) or the **web app** (XSS, SQLi). But modern AI agents have a fundamentally different attack surface:

- **Tools** that read files, query databases, and make HTTP requests
- **Memory** that persists across conversations
- **Multi-step reasoning** that chains tool calls together
- **Protocol endpoints** (REST, OpenAI, MCP, A2A) exposed over HTTPS

An agent with `read_file` and `http_request` has a **critical data exfiltration vulnerability** — even if neither tool is dangerous alone. No existing tool catches this.

## What ZIRAN Does

ZIRAN is the first open-source framework designed specifically for **agent security testing**:

!!! success "Core Capabilities"

    - :link: **Tool Chain Analysis** — Automatically detects dangerous tool combinations across 30+ known patterns
    - :shield: **Multi-Phase Trust Exploitation** — Progressive campaigns that build trust before testing boundaries
    - :globe_with_meridians: **Remote Agent Scanning** — Test any published agent over HTTPS (REST, OpenAI, MCP, A2A)
    - :world_map: **Knowledge Graph** — Every capability, relationship, and attack path tracked in a live graph
    - :bar_chart: **CI/CD Quality Gate** — Block deployments that fail security thresholds, with SARIF output
    - :mag: **Static Analysis** — Scan agent source code for vulnerabilities without running the agent

## Quick Demo

```bash
pip install ziran
git clone https://github.com/taoq-ai/ziran.git && cd ziran
uv sync --extra langchain

# Scan a vulnerable example agent
uv run python examples/10-vulnerable-agent/main.py
```

## How It Compares

| Capability | ZIRAN | Garak | Promptfoo | PyRIT | Shannon |
|---|:---:|:---:|:---:|:---:|:---:|
| Agent-aware (tools + memory) | **Yes** | — | Partial | — | — |
| Tool chain analysis | **Yes** | — | — | — | — |
| Multi-phase campaigns | **Yes** | — | — | Partial | Yes |
| Knowledge graph tracking | **Yes** | — | — | — | — |
| Remote agent scanning (HTTPS) | **Yes** | REST only | HTTP provider | Partial | — |
| Multi-protocol (REST/OpenAI/MCP/A2A) | **Yes** | — | — | — | — |
| A2A protocol support | **Yes** | — | — | — | — |
| CI/CD quality gate | **Yes** | — | Yes | — | Pro |

## Next Steps

- :rocket: [Getting Started](getting-started.md) — Your first scan in 5 minutes
- :brain: [Concepts](concepts/architecture.md) — Understand how ZIRAN works
- :books: [Scanning Agents](guides/scanning-agents.md) — Scan your own agents
- :test_tube: [Examples](https://github.com/taoq-ai/ziran/tree/main/examples) — 15 runnable examples from basic to advanced
