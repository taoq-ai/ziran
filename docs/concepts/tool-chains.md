# Tool Chain Analysis

**Tool Chain Analysis is ZIRAN's unique differentiator.** No other AI security testing tool automatically detects dangerous tool combinations.

## The Problem

An agent with `read_file` is not inherently dangerous. An agent with `http_request` is not inherently dangerous. But an agent with **both** has a critical data exfiltration vulnerability — an attacker can read local files and send their contents to an external server.

Traditional tools test individual prompts. ZIRAN reasons about **tool composition**.

## How It Works

After a scan campaign completes, ZIRAN's `ToolChainAnalyzer` examines the knowledge graph:

1. **Direct chains** — Tool A has a direct edge to Tool B, and (A, B) matches a known dangerous pattern
2. **Indirect chains** — Tools A and B are connected through intermediate nodes (A → X → B)
3. **Cycles** — Circular chains (A → B → C → A) that enable repeated exploitation

### Dangerous Pattern Database

ZIRAN ships with 30+ dangerous tool chain patterns:

| Category | Example | Risk |
|----------|---------|------|
| Data Exfiltration | `read_file` → `http_request` | Critical |
| SQL to RCE | `sql_query` → `execute_code` | Critical |
| PII Leakage | `get_user_info` → `external_api` | High |
| Privilege Escalation | `search_database` → `update_permissions` | Critical |
| File Manipulation | `read_file` → `write_file` | High |
| Remote Code Execution | `http_request` → `shell_execute` | Critical |
| Authentication Bypass | `read_config` → `generate_token` | Critical |
| Data Poisoning | `http_request` → `write_file` | High |
| Session Hijacking | `get_session` → `http_request` | Critical |
| MCP Exploitation | `mcp_list_servers` → `mcp_invoke` | High |

### Risk Scoring

Each chain receives a 0.0–1.0 risk score based on:

- **Base severity** — Critical (1.0), High (0.75), Medium (0.5), Low (0.25)
- **Chain type** — Direct (1.0×), Cycle (0.9×), Indirect (0.8×)
- **Graph centrality** — Bonus for tools that are central to many paths

## Using Chain Analysis

### Programmatic

```python
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer

analyzer = ToolChainAnalyzer(scanner.graph)
chains = analyzer.analyze()

for chain in chains:
    print(f"{chain.risk_level}: {' → '.join(chain.tools)}")
    print(f"  Type: {chain.vulnerability_type}")
    print(f"  Score: {chain.risk_score}")
    print(f"  Fix: {chain.remediation}")
```

### In Reports

Tool chains appear prominently in all report formats — HTML, Markdown, and JSON.

## Adding Custom Patterns

The pattern database is extensible. See the `DANGEROUS_PATTERNS` dictionary in `chain_analyzer.py`.
