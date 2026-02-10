# KOAN — AI Agent Security Testing

**KOAN** uses Romance Scan methodology and knowledge graphs to systematically discover vulnerabilities in AI agents.

## Why KOAN?

Traditional LLM testing tools check for prompt injection on single-turn conversations. **But modern AI agents have tools, memory, and multi-step reasoning** — creating attack surfaces that single-prompt tests miss entirely.

KOAN is the first open-source framework designed specifically for **agent security**:

- **🔗 Tool Chain Analysis** — Automatically detects dangerous tool combinations
- **🧪 Multi-phase Campaigns** — Progressive trust exploitation, like a real attacker
- **🗺️ Knowledge Graph** — Visual tracking of attack progression
- **🛡️ Skill CVE Database** — Known vulnerabilities in popular agent tools

## Quick Demo

```bash
pip install uv
git clone https://github.com/taoq-ai/koan.git && cd koan
uv sync --extra langchain

# Scan a vulnerable example agent
uv run python examples/vulnerable_agent.py
```

## Next Steps

- [Getting Started](getting-started.md) — Your first scan in 5 minutes
- [Concepts](concepts/romance-scan.md) — Understand how KOAN works
- [Guides](guides/scanning-agents.md) — Scan your own agents
