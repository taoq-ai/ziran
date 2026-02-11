# Getting Started

Get your first security scan running in under 5 minutes.

## Prerequisites

- **Python 3.11+**
- [**uv**](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

=== "uv (recommended)"

    ```bash
    git clone https://github.com/taoq-ai/ziran.git
    cd ziran
    uv sync
    ```

=== "pip"

    ```bash
    pip install ziran
    ```

### Framework Extras

Install support for your agent framework:

```bash
uv sync --extra langchain   # LangChain
uv sync --extra crewai      # CrewAI
uv sync --extra all          # Everything
```

## Your First Scan

### Option 1: CLI

```bash
ziran scan --framework langchain --agent-path my_agent.py
```

### Option 2: Python API

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

### Option 3: Example Script

```bash
uv run python examples/vulnerable_agent.py
```

## Understanding Results

After a scan, ZIRAN generates three reports in the output directory:

| File | Format | Use |
|------|--------|-----|
| `campaign_*_report.html` | Interactive HTML | Visual analysis with knowledge graph |
| `campaign_*_report.md` | Markdown | Human-readable summary |
| `campaign_*_report.json` | JSON | Programmatic analysis |

Open the HTML report for the richest experience:

```bash
open reports/campaign_*_report.html
```

## Next Steps

- [Romance Scan Methodology](concepts/romance-scan.md) — How multi-phase campaigns work
- [Tool Chain Analysis](concepts/tool-chains.md) — ZIRAN's unique differentiator
- [Scanning Agents](guides/scanning-agents.md) — Detailed scanning guide
