# ZIRAN -- AI Agent Security Testing

**Find vulnerabilities in AI agents -- not just LLMs, but agents with tools, memory, and multi-step reasoning.**

---

## The Problem

Most security tools test individual prompts or tools in isolation. But AI agents have a fundamentally different attack surface -- **tool combinations**:

- An agent with `read_file` and `http_request` has a **critical data exfiltration vulnerability** -- even if neither tool is dangerous alone
- An agent that says "I can't do that" but **executes the tool anyway** will pass text-based evaluation but fail in production
- Vulnerabilities that only emerge after **building trust across multiple interactions** are invisible to single-pass testing

ZIRAN discovers these composition-level risks through knowledge graph analysis, execution-level detection, and multi-phase campaigns.

## What ZIRAN Does

!!! success "Core Capabilities"

    - :link: **Tool Chain Analysis** -- Automatically detects dangerous tool combinations across 30+ known patterns
    - :shield: **Multi-Phase Trust Exploitation** -- Progressive campaigns that build trust before testing boundaries
    - :people_holding_hands: **Multi-Agent Coordination** -- Discover topologies and test cross-agent trust boundaries in supervisor, router, and peer-to-peer systems
    - :brain: **Adaptive Campaigns** -- Three execution strategies (fixed, rule-based adaptive, LLM-driven) that adjust attack plans based on findings
    - :zap: **Streaming Support** -- Real-time attack monitoring via SSE and WebSocket protocols
    - :globe_with_meridians: **Remote Agent Scanning** -- Test any published agent over HTTPS (REST, OpenAI, MCP, A2A)
    - :world_map: **Knowledge Graph** -- Every capability, relationship, and attack path tracked in a live graph
    - :bar_chart: **CI/CD Quality Gate** -- Block deployments that fail security thresholds, with SARIF output
    - :mag: **Static Analysis** -- Scan agent source code for vulnerabilities without running the agent

## Quick Demo

```bash
pip install ziran
git clone https://github.com/taoq-ai/ziran.git && cd ziran
uv sync --extra langchain

# Scan a vulnerable example agent
uv run python examples/10-vulnerable-agent/main.py
```

## How It Compares

| Capability | ZIRAN | Promptfoo | Invariant (Snyk) | Garak | PyRIT | Inspect AI |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Tool chain discovery (graph-based) | Yes | -- | Policy-based | -- | -- | -- |
| Side-effect detection (execution-level) | Yes | -- | Trace-based | -- | -- | Sandbox |
| Multi-phase campaigns w/ graph feedback | Yes | Turn-level | Flow analysis | -- | Composable | Multi-turn |
| Autonomous pentesting agent | Yes | -- | -- | -- | -- | -- |
| Multi-agent coordination | Yes | -- | -- | -- | -- | -- |
| Agent-aware (tools + memory) | Yes | Partial | Yes | -- | -- | Partial |
| A2A + MCP protocol support | Yes | MCP only | MCP only | -- | -- | -- |
| Encoding/obfuscation attacks | -- | Yes (12+) | -- | -- | -- | -- |
| Industry compliance plugins | -- | Yes (46) | -- | -- | -- | -- |
| CI/CD quality gate | Yes | Yes | -- | -- | -- | -- |

!!! info "What ZIRAN Is Not"

    ZIRAN focuses on agent-level security testing. For **LLM safety/alignment** (jailbreaks, compliance), use [Promptfoo](https://github.com/promptfoo/promptfoo) or [Garak](https://github.com/NVIDIA/garak). For **runtime guardrails**, use [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) or [Lakera Guard](https://www.lakera.ai/). For **model evaluation**, use [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) or [Deepeval](https://github.com/confident-ai/deepeval). ZIRAN is complementary to all of these.

## Next Steps

- :rocket: [Getting Started](getting-started.md) -- Your first scan in 5 minutes
- :brain: [Concepts](concepts/architecture.md) -- Understand how ZIRAN works
- :people_holding_hands: [Multi-Agent Scanning](concepts/multi-agent.md) -- Test coordinated agent systems
- :zap: [Streaming](concepts/streaming.md) -- Real-time attack monitoring
- :dart: [Adaptive Campaigns](concepts/adaptive-campaigns.md) -- Intelligent attack strategies
- :books: [Scanning Agents](guides/scanning-agents.md) -- Scan your own agents
- :test_tube: [Examples](https://github.com/taoq-ai/ziran/tree/main/examples) -- 18 runnable examples from basic to advanced
