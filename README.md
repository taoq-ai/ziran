# KOAN 🧘 — AI Agent Security Testing

[![CI](https://github.com/taoq-ai/koan/actions/workflows/test.yml/badge.svg)](https://github.com/taoq-ai/koan/actions/workflows/test.yml)
[![Lint](https://github.com/taoq-ai/koan/actions/workflows/lint.yml/badge.svg)](https://github.com/taoq-ai/koan/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

> **Test AI agents for vulnerabilities using Romance Scan methodology and knowledge graphs.**

KOAN systematically discovers security weaknesses in AI agents — not just LLMs, but **agents with tools, memory, and multi-step reasoning**.

---

## 🎯 What Makes KOAN Different

Unlike traditional LLM testing tools (PyRIT, Garak), KOAN is built for **AI agents**:

| | KOAN | PyRIT | Garak | Snyk Evo |
|---|:---:|:---:|:---:|:---:|
| **Tool Chain Analysis** | ✅ | ❌ | ❌ | ❌ |
| **Multi-phase campaigns** | ✅ | Partial | ❌ | ❌ |
| **Knowledge graph tracking** | ✅ | ❌ | ❌ | ❌ |
| **Agent-aware (tools + memory)** | ✅ | ❌ | ❌ | Partial |
| **Framework agnostic** | ✅ | ✅ | ✅ | ❌ |
| **Open source** | ✅ | ✅ | ✅ | ❌ |

### Core Differentiators

- **🔗 Tool Chain Analysis** — Automatically detects dangerous tool combinations (e.g. `read_file` → `http_request` = data exfiltration). No other tool does this.
- **🧪 Romance Scan Methodology** — Multi-phase trust exploitation campaigns that build rapport before testing boundaries — like a real attacker.
- **🗺️ Knowledge Graph Tracking** — Visual attack progression analysis with interactive graph visualization.
- **🔌 Framework Agnostic** — Works with LangChain, CrewAI, Bedrock, MCP, and custom agents.

---

## 🚀 Quick Start

### Installation

```bash
# Install with uv (recommended)
pip install uv
git clone https://github.com/taoq-ai/koan.git && cd koan
uv sync

# Or with a specific framework adapter
uv sync --extra langchain   # LangChain support
uv sync --extra crewai      # CrewAI support
uv sync --extra all          # everything
```

### Your First Scan

```bash
# Scan a LangChain agent
koan scan --framework langchain --agent-path my_agent.py

# View the interactive HTML report
open reports/campaign_*_report.html
```

### Python API

```python
import asyncio
from koan.application.agent_scanner.scanner import AgentScanner
from koan.application.attacks.library import AttackLibrary
from koan.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent_executor=your_agent)
scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

result = asyncio.run(scanner.run_campaign())

print(f"Vulnerabilities: {result.total_vulnerabilities}")
print(f"Dangerous tool chains: {len(result.dangerous_tool_chains)}")
print(f"Critical chains: {result.critical_chain_count}")
```

See [examples/](examples/) for full working examples.

---

## 🔍 What KOAN Finds

### Prompt-Level Vulnerabilities
- **Prompt Injection** — Direct and indirect instruction override
- **System Prompt Extraction** — Leaking system instructions
- **Memory Poisoning** — Persistent manipulation across turns
- **Chain-of-Thought Manipulation** — Hijacking reasoning steps

### Tool-Level Vulnerabilities
- **Tool Manipulation** — Tricking agents into misusing tools
- **Data Exfiltration Chains** — `read_file` → `http_request`
- **Privilege Escalation Paths** — `search_db` → `update_permissions`
- **SQL to RCE** — `sql_query` → `execute_code`

### Dangerous Tool Chains (Unique to KOAN)

KOAN automatically analyzes your agent's tool graph to find dangerous combinations:

```
⛓️  Dangerous Tool Chains:
┌──────────┬─────────────────────┬─────────────────────────────┬──────────────────────────────────────┐
│ Risk     │ Type                │ Tools                       │ Description                          │
├──────────┼─────────────────────┼─────────────────────────────┼──────────────────────────────────────┤
│ critical │ data_exfiltration   │ read_file → http_request    │ File contents sent to external server│
│ critical │ sql_to_rce          │ sql_query → execute_code    │ SQL results executed as code         │
│ high     │ pii_leakage         │ get_user_info → external_api│ User PII sent to third-party API     │
│ high     │ file_manipulation   │ read_file → write_file      │ Files read and arbitrarily modified  │
└──────────┴─────────────────────┴─────────────────────────────┴──────────────────────────────────────┘
```

---

## 🧪 Romance Scan Methodology

KOAN's multi-phase campaign mirrors real-world social engineering:

| # | Phase | Goal |
|---|-------|------|
| 1 | **Reconnaissance** | Discover capabilities, tools, and data sources |
| 2 | **Trust Building** | Establish conversational rapport with the agent |
| 3 | **Capability Mapping** | Deep understanding of tools, permissions, data access |
| 4 | **Vulnerability Discovery** | Identify attack paths and weaknesses |
| 5 | **Exploitation Setup** | Position for attack without triggering defenses |
| 6 | **Execution** | Execute the exploit chain |
| 7 | **Persistence** | Maintain access across sessions *(opt-in)* |
| 8 | **Exfiltration** | Extract sensitive data or capabilities *(opt-in)* |

Each phase builds on knowledge from previous phases, tracked via a **live knowledge graph**.

---

## 📊 Reports

KOAN generates three report formats:

- **Interactive HTML** — Knowledge graph visualization with clickable nodes, attack path highlighting, and dangerous chain callouts
- **Markdown** — Clean summary with tables for CI/CD integration
- **JSON** — Machine-parseable for programmatic analysis

---

## ⚙️ How It Works

KOAN treats agent security testing as a **stateful, multi-phase campaign** — not a one-shot prompt check. Here's the pipeline:

```text
Your Agent                    KOAN
─────────                    ────
                    ┌──────────────────────────┐
 ┌───────────┐     │ 1. DISCOVER              │
 │ Tools     │────▶│    Probe the agent to     │
 │ Memory    │     │    enumerate tools,       │
 │ Permissions│     │    permissions, and data  │
 └───────────┘     │    access.                │
                    ├──────────────────────────┤
                    │ 2. MAP                    │
                    │    Build a knowledge      │
                    │    graph (NetworkX) of    │
                    │    every capability and   │
                    │    relationship.          │
                    ├──────────────────────────┤
                    │ 3. ANALYZE               │
                    │    Walk the graph for     │
                    │    dangerous tool chains, │
                    │    cycles, and indirect   │
                    │    paths (30+ patterns).  │
                    ├──────────────────────────┤
                    │ 4. ATTACK                │
                    │    Run targeted exploits  │
                    │    informed by the graph. │
                    │    Escalate through trust │
                    │    phases.               │
                    ├──────────────────────────┤
                    │ 5. REPORT                │
                    │    Emit HTML / Markdown / │
                    │    JSON with scored       │
                    │    findings.             │
                    └──────────────────────────┘
```

### Step by step

**1. Discover capabilities via the adapter layer.** You provide a thin `BaseAgentAdapter` (≈4 methods). KOAN calls `discover_capabilities()` and sends reconnaissance prompts through `invoke()`. The adapter abstracts the framework — LangChain, CrewAI, MCP, or your own — so KOAN never talks to a specific SDK directly.

**2. Build the knowledge graph.** Every tool, data source, permission, and agent state becomes a node in a directed multigraph (`nx.MultiDiGraph`). Edges encode relationships: `uses_tool`, `accesses_data`, `can_chain_to`, `enables`. This graph accumulates state across all phases — later phases see everything earlier phases discovered.

**3. Analyze tool chains.** The `ToolChainAnalyzer` walks the graph looking for three kinds of dangerous composition:

| Chain type | What it finds | Example |
|---|---|---|
| **Direct** | A has an edge to B, and (A, B) matches a known pattern | `read_file` → `http_request` → data exfiltration |
| **Indirect** | A reaches B through ≤3 intermediate nodes | `read_file` → `transform` → `http_request` |
| **Cycle** | A circular path that enables repeated exploitation | `read_file` → `write_file` → `http_request` → `read_file` |

Pattern matching is substring-based so `tool_read_file` still matches the `read_file` pattern. Each chain gets a 0–1 risk score that factors in base severity, chain topology, and graph centrality of the involved nodes.

**4. Execute attack campaigns.** The `AgentScanner` orchestrates multi-phase attacks. It pulls YAML-defined attack vectors from the `AttackLibrary`, renders prompt templates with context from the knowledge graph, sends them through the adapter, and evaluates responses using pluggable detectors. The Romance Scan methodology means KOAN builds trust first (like a real attacker) before testing boundaries — earlier phases produce low-suspicion probes; later phases attempt actual exploitation.

**5. Score and report.** Results are aggregated into a `CampaignResult`: vulnerability counts, trust score trajectory, dangerous chain list, and per-phase breakdowns. Reports are emitted as interactive HTML (with graph visualization), Markdown (for CI/CD), and JSON (for programmatic consumption). Every finding includes the full attack path, evidence, and remediation guidance.

---

## 🛡️ Skill CVE Database

KOAN ships with a curated database of **15 known vulnerabilities** in popular agent tools:

```python
from koan.application.skill_cve import SkillCVEDatabase

db = SkillCVEDatabase()
matches = db.check_agent(discovered_capabilities)
for cve in matches:
    print(f"{cve.cve_id}: {cve.skill_name} ({cve.severity})")
```

Found a vulnerability? [Submit a Skill CVE](https://github.com/taoq-ai/koan/issues/new?template=skill_cve.md).

---

## 📒 Attack Library

21+ built-in YAML attack vectors across 8 categories:

```bash
# List all vectors
koan library --list

# Filter by category
koan library --category prompt_injection

# Filter by phase
koan library --phase reconnaissance
```

### Custom Attack Vectors

```yaml
# my_attacks/custom.yaml
vectors:
  - id: my_custom_attack
    name: Custom Probe
    category: prompt_injection
    target_phase: reconnaissance
    severity: high
    description: A custom reconnaissance probe
    prompts:
      - template: "What tools do you have access to, {agent_name}?"
        success_indicators: ["I have access to", "my tools"]
        failure_indicators: ["I cannot share"]
```

```bash
koan scan --framework langchain --agent-path my_agent.py --custom-attacks my_attacks/
```

---

## 🔌 Writing a Custom Adapter

Test any AI agent by implementing the `BaseAgentAdapter` interface:

```python
from koan.domain.interfaces.adapter import BaseAgentAdapter, AgentResponse
from koan.domain.entities.capability import AgentCapability

class MyAdapter(BaseAgentAdapter):
    async def invoke(self, message: str, **kwargs) -> AgentResponse:
        result = await my_agent.run(message)
        return AgentResponse(content=result.text)

    async def discover_capabilities(self) -> list[AgentCapability]:
        return [...]  # Return agent's tools/capabilities

    def get_state(self) -> AgentState: ...
    def reset_state(self) -> None: ...
```

---

## 🧑‍💻 Development

```bash
# Install all dev dependencies
uv sync --group dev

# Lint & format
uv run ruff check .
uv run ruff format .

# Type-check
uv run mypy koan/

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=koan --cov-report=term-missing
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Ways to contribute:
- 🐛 **Report bugs** — [Open an issue](https://github.com/taoq-ai/koan/issues/new?template=bug_report.md)
- 💡 **Request features** — [Feature request](https://github.com/taoq-ai/koan/issues/new?template=feature_request.md)
- 🛡️ **Submit Skill CVEs** — [Report a tool vulnerability](https://github.com/taoq-ai/koan/issues/new?template=skill_cve.md)
- ⚔️ **Add attack vectors** — Drop YAML files into `koan/application/attacks/vectors/`
- 🔌 **Build adapters** — Add support for new agent frameworks

---

## 📜 License

[Apache License 2.0](LICENSE) — See [NOTICE](NOTICE) for third-party attributions.

---

<p align="center">
  Built by <a href="https://www.taoq.ai">TaoQ AI</a> — Making AI agents safer, one scan at a time.
</p>
