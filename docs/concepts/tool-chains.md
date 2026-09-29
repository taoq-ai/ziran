# Tool Chain Analysis

## The Problem

An agent with `read_file` is not inherently dangerous. An agent with `http_request` is not inherently dangerous. But an agent with **both** has a critical data exfiltration vulnerability -- an attacker can read local files and send their contents to an external server.

Security reviews that examine tools individually will approve both. The vulnerability only exists in their **composition** -- and that's what tool chain analysis detects.

## Why Graph-Based Detection Matters

List-based testing checks each tool against a blocklist. Policy-based approaches define rules for known-bad combinations. Both miss transitive chains -- when tool A connects to tool B through an intermediate tool C that is not itself dangerous.

Graph-based analysis builds a directed graph of all tool relationships and walks it for dangerous paths. This catches:

- **Direct chains** -- Tool A has a direct edge to Tool B, and (A, B) matches a known dangerous pattern
- **Indirect chains** -- Tools A and B are connected through intermediate nodes (A -> X -> B)
- **Cycles** -- Circular chains (A -> B -> C -> A) that enable repeated exploitation

## Dangerous Pattern Database

ZIRAN ships with 30+ dangerous tool chain patterns:

| Category | Example | Risk |
|----------|---------|------|
| Data Exfiltration | `read_file` -> `http_request` | Critical |
| SQL to RCE | `sql_query` -> `execute_code` | Critical |
| PII Leakage | `get_user_info` -> `external_api` | High |
| Privilege Escalation | `search_database` -> `update_permissions` | Critical |
| File Manipulation | `read_file` -> `write_file` | High |
| Remote Code Execution | `http_request` -> `shell_execute` | Critical |
| Authentication Bypass | `read_config` -> `generate_token` | Critical |
| Data Poisoning | `http_request` -> `write_file` | High |
| Session Hijacking | `get_session` -> `http_request` | Critical |
| MCP Exploitation | `mcp_list_servers` -> `mcp_invoke` | High |

## Claude Code tool names

Claude Code tools (`Read`, `Bash`, `mcp__slack__slack_send_message`, ...) do not share keywords
with the patterns above. Before matching, the analyzer resolves each tool id with
`canonical_tool_name` from `ziran.application.knowledge_graph.tool_aliases`, the single alias
map shared with trace analysis. Reported chains keep the original tool names.

| Claude Code tool | Matched as |
|------------------|------------|
| `Read`, `Grep`, `Glob` | `read_file` |
| `Write`, `Edit`, `NotebookEdit` | `write_file` |
| `Bash` | `shell_execute` |
| `WebFetch` | `http_request` |
| `WebSearch` | `browse_url` |
| `Agent` | `spawn_subagent` |
| `mcp__<server>__<tool>` whose first tool word (ignoring server words) is `send`, `post`, `create`, `reply`, `publish` or `update` | `send_email` (outbound message) |

Matching is exact and case-sensitive; any other id is left unchanged. Tool lists carry no call
arguments, so argument-specific risks use the Claude Code permission-rule form `Name(specifier)`:

- `Read(./.env)`, `Read(~/.ssh/id_rsa)`, `Grep(.aws/credentials)`, `Read(*.pem)` and other secret
  paths match as `read_secret_file`.
- `Bash(git push:*)` matches as `git_push`. Other scoped rules such as `Bash(npm test:*)` match as
  `shell_execute`.

Claude Code patterns (checked before the generic ones):

| Chain | Type | Risk |
|-------|------|------|
| `read_secret_file` -> `send_email` | `secret_file_exfiltration` | Critical |
| `read_file` -> `git_push` | `code_exfiltration` | Critical |
| `spawn_subagent` -> `shell_execute` | `delegation_to_rce` | Critical |
| `spawn_subagent` -> `http_request` | `cross_agent_exfiltration` | High |
| `spawn_subagent` -> `write_file` | `cross_agent_persist` | High |

An unscoped `Bash` (or `Bash(*)`) tool is also reported on its own as a single-tool
`unrestricted_execution` finding with risk `high`. Scoped `Bash(...)` rules are not. Cedar policy
generation skips single-tool findings.

`ziran analyze-traces` builds the same graph from trace tool calls, so it uses the same names.

## Risk Scoring

Each chain receives a 0.0--1.0 risk score based on:

- **Base severity** -- Critical (1.0), High (0.75), Medium (0.5), Low (0.25)
- **Chain type** -- Direct (1.0x), Cycle (0.9x), Indirect (0.8x)
- **Graph centrality** -- Bonus for tools that are central to many paths

## Using Chain Analysis

### Programmatic

```python
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer

analyzer = ToolChainAnalyzer(scanner.graph)
chains = analyzer.analyze()

for chain in chains:
    print(f"{chain.risk_level}: {' -> '.join(chain.tools)}")
    print(f"  Type: {chain.vulnerability_type}")
    print(f"  Score: {chain.risk_score}")
    print(f"  Fix: {chain.remediation}")
```

### In Reports

Tool chains appear prominently in all report formats -- HTML, Markdown, and JSON.

## Adding Custom Patterns

The pattern database is extensible. See the `DANGEROUS_PATTERNS` dictionary in `chain_analyzer.py`.
