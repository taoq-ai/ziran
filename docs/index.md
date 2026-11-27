# ZIRAN -- AI Agent Security Testing

**ZIRAN finds the vulnerabilities in AI agents that come from tools combining, not from any single prompt.**

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

## Quick Example

```bash
pip install ziran
git clone https://github.com/taoq-ai/ziran.git
cd ziran/examples/24-claude-code-agent-audit

# Audit a Claude Code subagent with Read + WebFetch; no API key needed
ziran audit agents/
# CC001  critical  Agent 'researcher': data_exfiltration via Read -> WebFetch

# Full campaign against a deliberately vulnerable LangChain agent (needs OPENAI_API_KEY)
cd ../.. && uv sync --extra langchain && uv run python examples/10-vulnerable-agent/main.py
```

## How It Works

![ZIRAN pipeline diagram: your agent connects through an adapter layer into the pipeline. DISCOVER probes capabilities, MAP builds a NetworkX MultiDiGraph, ANALYZE walks the graph for dangerous chains, ATTACK runs multi-phase exploits informed by the graph, and REPORT emits scored findings as HTML, Markdown and JSON.](assets/pipeline-light.svg)

Five stages. **DISCOVER** probes tools, permissions and data access. **MAP** builds a NetworkX graph of capabilities. **ANALYZE** walks the graph against 30+ dangerous-chain patterns (`ziran audit` stops here). **ATTACK** runs an 8-phase campaign (reconnaissance, trust building, capability mapping, vulnerability discovery, exploitation setup, execution, persistence, exfiltration) where the live graph picks the next phase, so a critical chain found mid-campaign routes straight to exploitation and phases the graph shows to be pointless are skipped. **REPORT** emits scored findings with remediation guidance.

Two more things ZIRAN checks that text-only scanners cannot:

- **Side effects at the execution layer.** An agent can answer "I can't do that" and still fire `delete_user(id=42)` underneath. ZIRAN intercepts the tool call, not the chat reply.
- **Trust between agents.** In supervisor, router and peer-to-peer systems, an agent that accepts peer messages without validation is a lateral movement path.

Campaign strategies: `fixed` (sequential, reproducible for CI), `adaptive` (rule-based reordering) and `llm-adaptive` (an LLM reads the graph after each phase and plans the next). See [Adaptive Campaigns](concepts/adaptive-campaigns.md).

## How It Compares

| Capability | ZIRAN | [Promptfoo](https://github.com/promptfoo/promptfoo) | [Invariant](https://invariantlabs.ai/) (Snyk) | [Garak](https://github.com/NVIDIA/garak) | [PyRIT](https://github.com/Azure/PyRIT) | [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Tool chain discovery (graph-based) | Yes | -- | Policy-based | -- | -- | -- |
| Side-effect detection (execution-level) | Yes | -- | Trace-based | -- | -- | Sandbox |
| Multi-phase campaigns w/ graph feedback | Yes | Turn-level | Flow analysis | -- | Composable | Multi-turn |
| Autonomous pentesting agent | Yes | -- | -- | -- | -- | -- |
| Multi-agent coordination | Yes | -- | -- | -- | -- | -- |
| Knowledge graph tracking | Yes | -- | Policy lang. | -- | -- | -- |
| Agent-aware (tools + memory) | Yes | Partial | Yes | -- | -- | Partial |
| A2A protocol support | Yes | -- | -- | -- | -- | -- |
| MCP protocol support | Yes | Partial | Yes | -- | -- | -- |
| Encoding/obfuscation attacks | Yes (8) | Yes (12+) | -- | -- | -- | -- |
| Industry compliance plugins | -- | Yes (46) | -- | -- | -- | -- |
| Streaming (SSE/WebSocket) | Yes | -- | -- | -- | -- | -- |
| CI/CD quality gate | Yes | Yes | -- | -- | -- | -- |
| License | FSL-1.1-ALv2 (source-available) | MIT | Partial | Apache-2.0 | MIT | MIT |

!!! info "What ZIRAN Is Not"

    ZIRAN is not an LLM safety or alignment tool (use [Promptfoo](https://github.com/promptfoo/promptfoo) or [Garak](https://github.com/NVIDIA/garak) for jailbreak breadth and compliance), not a runtime guardrail ([NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails), [Lakera Guard](https://www.lakera.ai/), [LLM Guard](https://github.com/protectai/llm-guard)), and not a general eval framework ([Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai), [Deepeval](https://github.com/confident-ai/deepeval)). It sits next to them: Promptfoo or Garak for attack breadth, ZIRAN for agent depth; guardrails at runtime, ZIRAN before deploy; [Langfuse](https://langfuse.com/) or [LangSmith](https://smith.langchain.com/) for traces, ZIRAN `analyze-traces` to score them. Full mapping in the [Agent Security Landscape](concepts/agent-security-landscape.md).

## Next Steps

- :rocket: [Getting Started](getting-started.md) -- Your first scan in 5 minutes
- :brain: [Concepts](concepts/architecture.md) -- Understand how ZIRAN works
- :people_holding_hands: [Multi-Agent Scanning](concepts/multi-agent.md) -- Test coordinated agent systems
- :zap: [Streaming](concepts/streaming.md) -- Real-time attack monitoring
- :dart: [Adaptive Campaigns](concepts/adaptive-campaigns.md) -- Intelligent attack strategies
- :books: [Scanning Agents](guides/scanning-agents.md) -- Scan your own agents
- :test_tube: [Examples](https://github.com/taoq-ai/ziran/tree/main/examples) -- 18 runnable examples from basic to advanced

## Citation

```bibtex
@software{ziran2026,
  title     = {ZIRAN: AI Agent Security Testing},
  author    = {{TaoQ AI} and Lage Perdigao, Leone},
  year      = {2026},
  url       = {https://github.com/taoq-ai/ziran},
  license   = {FSL-1.1-ALv2}
}
```
