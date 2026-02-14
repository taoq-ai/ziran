# Getting Started

Get your first security scan running in under 5 minutes.

!!! info "What you'll learn"

    1. Install ZIRAN with your preferred framework
    2. Run your first agent scan (local or remote)
    3. Read the HTML report and understand findings
    4. Set up a CI/CD quality gate

## Prerequisites

- **Python 3.11+**
- [**uv**](https://docs.astral.sh/uv/) (recommended) or pip
- An **API key** for your LLM provider (for live scans — not required for static analysis or offline examples)

## Installation

=== "uv (recommended)"

    ```bash
    pip install uv
    pip install ziran
    ```

=== "pip"

    ```bash
    pip install ziran
    ```

### Framework Extras

Install support for your agent framework:

```bash
pip install ziran[langchain]   # LangChain agents
pip install ziran[crewai]      # CrewAI agents
pip install ziran[a2a]         # A2A protocol (Agent-to-Agent)
pip install ziran[all]         # Everything
```

## Your First Scan

### Option 1: Scan a Local Agent (CLI)

```bash
ziran scan --framework langchain --agent-path my_agent.py
```

Your agent file should export an `agent_executor` (LangChain) or `crew` (CrewAI) object.

### Option 2: Scan a Remote Agent

Create a target configuration file:

```yaml
# target.yaml
name: "My Agent"
url: "https://my-agent.example.com"
protocol: openai   # rest | openai | mcp | a2a | auto
auth:
  type: bearer
  token_env: MY_API_KEY
```

Then scan it:

```bash
ziran scan --target target.yaml
```

ZIRAN auto-detects the protocol if you set `protocol: auto`.

### Option 3: Python API

```python
import asyncio
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent_executor=your_agent)
scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
result = asyncio.run(scanner.run_campaign())

print(f"Found {result.total_vulnerabilities} vulnerabilities")
print(f"Dangerous tool chains: {len(result.dangerous_tool_chains)}")
```

### Option 4: Run an Example

ZIRAN ships with 15 examples — from static analysis to multi-agent scanning:

```bash
git clone https://github.com/taoq-ai/ziran.git && cd ziran
uv sync --extra langchain

# No API key required
uv run python examples/01-static-analysis/main.py

# Requires OPENAI_API_KEY
uv run python examples/10-vulnerable-agent/main.py
```

See the full [examples catalog](https://github.com/taoq-ai/ziran/tree/main/examples).

## Understanding Results

After a scan, ZIRAN generates reports in the output directory:

| File | Format | Best For |
|------|--------|----------|
| `campaign_*_report.html` | Interactive HTML | Visual analysis with knowledge graph |
| `campaign_*_report.md` | Markdown | Code reviews and CI/CD pipelines |
| `campaign_*_report.json` | JSON | Programmatic consumption |
| `*.sarif` | SARIF | GitHub Security tab integration |

Open the HTML report for the richest experience:

```bash
open reports/campaign_*_report.html
```

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **Critical** | Immediate exploitation possible | Fix immediately |
| **High** | Significant risk with effort | Fix before production |
| **Medium** | Moderate risk, specific conditions | Plan remediation |
| **Low** | Minor / informational | Monitor |

### Key Sections in the Report

- **Campaign Summary** — Pass/fail status, trust score, vulnerability count
- **Knowledge Graph** — Interactive visualization of agent capabilities and attack paths
- **Tool Chain Findings** — Dangerous tool combinations with remediation steps
- **Phase Timeline** — Detailed results from each scan phase
- **OWASP Mapping** — Findings mapped to OWASP Top 10 for LLM Applications

## What's Next?

| Goal | Guide |
|------|-------|
| Understand how multi-phase scanning works | [Trust Exploitation Methodology](concepts/romance-scan.md) |
| Learn about tool chain analysis | [Tool Chain Analysis](concepts/tool-chains.md) |
| Scan remote agents over HTTPS | [Remote Agent Scanning](guides/remote-agents.md) |
| Set up CI/CD quality gates | [CI/CD Integration](guides/cicd-integration.md) |
| Scan source code without running agents | [Static Analysis](guides/static-analysis.md) |
| Write custom attack vectors | [Custom Attacks](guides/custom-attacks.md) |
| Build an adapter for your framework | [Framework Adapters](guides/adapters.md) |
