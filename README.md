<div align="center">

# ZIRAN 🧘

### AI Agent Security Testing

[![CI](https://github.com/taoq-ai/ziran/actions/workflows/test.yml/badge.svg)](https://github.com/taoq-ai/ziran/actions/workflows/test.yml)
[![Lint](https://github.com/taoq-ai/ziran/actions/workflows/lint.yml/badge.svg)](https://github.com/taoq-ai/ziran/actions/workflows/lint.yml)
[![PyPI](https://img.shields.io/pypi/v/ziran.svg)](https://pypi.org/project/ziran/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

**Find vulnerabilities in AI agents — not just LLMs, but agents with tools, memory, and multi-step reasoning.**

![ZIRAN Demo](docs/assets/demo.gif)

[Install](#install) · [Quick Start](#quick-start) · [Examples](examples/) · [Docs](https://taoq-ai.github.io/ziran/)

</div>

---

## Why ZIRAN?

Most security tools test the **LLM** (prompt injection, jailbreaks) or the **web app** (XSS, SQLi).
ZIRAN tests the **AI agent** — the system that wields tools, retains memory, and chains reasoning.
That's a fundamentally different attack surface.

| Capability | ZIRAN | [Garak](https://github.com/NVIDIA/garak) | [Promptfoo](https://github.com/promptfoo/promptfoo) | [PyRIT](https://github.com/Azure/PyRIT) | [Shannon](https://github.com/KeygraphHQ/shannon) |
|---|:---:|:---:|:---:|:---:|:---:|
| Agent-aware (tools + memory) | **Yes** | — | Partial | — | — |
| Tool chain analysis | **Yes** | — | — | — | — |
| Multi-phase campaigns | **Yes** | — | — | Partial | Yes |
| Knowledge graph tracking | **Yes** | — | — | — | — |
| CI/CD quality gate | **Yes** | — | Yes | — | Pro |
| Open source | Apache-2.0 | Apache-2.0 | MIT | MIT | AGPL-3.0 |

**Key differentiators:**

- **Tool Chain Analysis** — Detects dangerous tool combinations (`read_file` → `http_request` = data exfiltration). No other tool does this.
- **Romance Scan** — Multi-phase campaigns that build trust before testing boundaries, like a real attacker.
- **Knowledge Graph** — Every discovered capability, relationship, and attack path is tracked in a live graph.
- **Framework Agnostic** — LangChain, CrewAI, MCP, or [write your own adapter](examples/08-custom-adapter/).

---

## Install

```bash
pip install ziran

# with framework adapters
pip install ziran[langchain]    # LangChain support
pip install ziran[crewai]       # CrewAI support
pip install ziran[all]          # everything
```

---

## Quick Start

### CLI

```bash
# scan a LangChain agent
ziran scan --framework langchain --agent-path my_agent.py

# view the interactive HTML report
open reports/campaign_*_report.html
```

### Python API

```python
import asyncio
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent=your_agent)
scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

result = asyncio.run(scanner.run_campaign())
print(f"Vulnerabilities found: {result.total_vulnerabilities}")
print(f"Dangerous tool chains: {len(result.dangerous_tool_chains)}")
```

See [examples/](examples/) for 14 runnable demos — from static analysis to multi-agent supervisor scans.

---

## What ZIRAN Finds

**Prompt-level** — injection, system prompt extraction, memory poisoning, chain-of-thought manipulation.

**Tool-level** — tool manipulation, privilege escalation, data exfiltration chains.

**Tool chains** (unique to ZIRAN) — automatic graph analysis of dangerous tool compositions:

```
┌──────────┬─────────────────────┬─────────────────────────────┬──────────────────────────────────────┐
│ Risk     │ Type                │ Tools                       │ Description                          │
├──────────┼─────────────────────┼─────────────────────────────┼──────────────────────────────────────┤
│ critical │ data_exfiltration   │ read_file → http_request    │ File contents sent to external server│
│ critical │ sql_to_rce          │ sql_query → execute_code    │ SQL results executed as code         │
│ high     │ pii_leakage         │ get_user_info → external_api│ User PII sent to third-party API     │
└──────────┴─────────────────────┴─────────────────────────────┴──────────────────────────────────────┘
```

---

## How It Works

```mermaid
flowchart LR
    subgraph agent["🤖 Your Agent"]
        direction TB
        T["🔧 Tools"]
        M["🧠 Memory"]
        P["🔑 Permissions"]
    end

    agent -->|"adapter layer"| D

    subgraph ziran["⛩️ ZIRAN Pipeline"]
        direction TB
        D["1 · DISCOVER\nProbe tools, permissions,\ndata access"]
        MAP["2 · MAP\nBuild knowledge graph\n(NetworkX MultiDiGraph)"]
        A["3 · ANALYZE\nWalk graph for dangerous\nchains (30+ patterns)"]
        ATK["4 · ATTACK\nMulti-phase exploits\ninformed by the graph"]
        R["5 · REPORT\nScored findings with\nremediation guidance"]
        D --> MAP --> A --> ATK --> R
    end

    R --> HTML["📊 HTML\nInteractive graph"]
    R --> MD["📝 Markdown\nCI/CD tables"]
    R --> JSON["📦 JSON\nMachine-parseable"]

    style agent fill:#1a1a2e,stroke:#e94560,color:#fff,stroke-width:2px
    style ziran fill:#0f3460,stroke:#e94560,color:#fff,stroke-width:2px
    style D fill:#16213e,stroke:#0ea5e9,color:#fff
    style MAP fill:#16213e,stroke:#0ea5e9,color:#fff
    style A fill:#16213e,stroke:#0ea5e9,color:#fff
    style ATK fill:#16213e,stroke:#e94560,color:#fff
    style R fill:#16213e,stroke:#10b981,color:#fff
    style HTML fill:#1e293b,stroke:#10b981,color:#fff
    style MD fill:#1e293b,stroke:#10b981,color:#fff
    style JSON fill:#1e293b,stroke:#10b981,color:#fff
    style T fill:#2d2d44,stroke:#e94560,color:#fff
    style M fill:#2d2d44,stroke:#e94560,color:#fff
    style P fill:#2d2d44,stroke:#e94560,color:#fff
```

### Romance Scan Phases

| Phase | Goal |
|-------|------|
| Reconnaissance | Discover capabilities and data sources |
| Trust Building | Establish rapport with the agent |
| Capability Mapping | Map tools, permissions, data access |
| Vulnerability Discovery | Identify attack paths |
| Exploitation Setup | Position without triggering defences |
| Execution | Execute the exploit chain |
| Persistence | Maintain access across sessions *(opt-in)* |
| Exfiltration | Extract sensitive data *(opt-in)* |

Each phase builds on the knowledge graph from previous phases.

---

## Reports

Three output formats, generated automatically:

- **HTML** — Interactive knowledge graph with attack path highlighting
- **Markdown** — CI/CD-friendly summary tables
- **JSON** — Machine-parseable for programmatic consumption

<div align="center">
  <img src="docs/assets/report.png" alt="ZIRAN HTML Report" width="800">
</div>

---

## CI/CD Integration

Use ZIRAN as a quality gate in your pipeline:

### Live scan (runs the full attack suite against your agent)

```yaml
# .github/workflows/security.yml
- uses: taoq-ai/ziran@v1
  with:
    command: scan
    framework: langchain        # langchain | crewai | bedrock
    agent-path: my_agent.py
    coverage: standard           # essential | standard | comprehensive
    gate-config: gate_config.yaml
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}   # or ANTHROPIC_API_KEY, etc.
```

### Offline CI gate (evaluate a previous scan result)

```yaml
- uses: taoq-ai/ziran@v1
  with:
    command: ci
    result-file: scan_results/campaign_report.json
    gate-config: gate_config.yaml
```

**Outputs:** `status` (passed/failed), `trust-score`, `total-findings`, `critical-findings`, `sarif-file`.

See the [full example workflow](examples/07-cicd-quality-gate/ziran-scan.yml) or use the [Python API](examples/07-cicd-quality-gate/).

---

## Development

```bash
git clone https://github.com/taoq-ai/ziran.git && cd ziran
uv sync --group dev

uv run ruff check .            # lint
uv run mypy ziran/             # type-check
uv run pytest --cov=ziran      # test
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Ways to help:

- [Report bugs](https://github.com/taoq-ai/ziran/issues/new?template=bug_report.md)
- [Request features](https://github.com/taoq-ai/ziran/issues/new?template=feature_request.md)
- [Submit Skill CVEs](https://github.com/taoq-ai/ziran/issues/new?template=skill_cve.md) for tool vulnerabilities
- Add [attack vectors](ziran/application/attacks/vectors/) (YAML) or [adapters](ziran/infrastructure/adapters/)

---

## License

[Apache License 2.0](LICENSE) — See [NOTICE](NOTICE) for third-party attributions.

<p align="center">
  Built by <a href="https://www.taoq.ai">TaoQ AI</a>
</p>
