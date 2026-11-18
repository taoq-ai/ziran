# Ground Truth Dataset for Accuracy Measurement

A labeled dataset of 62 scenarios (33 true-positive, 29 true-negative) for measuring ZIRAN's detection precision, recall, and F1 score.

## Dataset Structure

```
ground_truth/
    agents/                    # 28 agent definitions (14 vulnerable + 14 safe)
    scenarios/
        tool_chain/            # 26 scenarios (14 TP, 12 TN)
        side_effect/           # 18 scenarios (10 TP, 8 TN)
        campaign/              # 18 scenarios (9 TP, 9 TN)
    schema.py                  # Pydantic validation models
    validate.py                # Dataset validation script
```

## Agent Archetypes

Each archetype has a vulnerable and safe (mitigated) version:

| Archetype | Framework | Inspired By |
|---|---|---|
| Enterprise Helpdesk | LangChain | CVE-2025-32711 (M365 Copilot), CVE-2025-8709 |
| Code Assistant | LangChain | CVE-2026-29783 (Copilot CLI), CVE-2025-64439 |
| MCP Research | MCP | CVE-2025-53109, CVE-2025-53110, CVE-2025-68145 |
| Data Analyst | LangChain+LangGraph | CVE-2025-8709, CVE-2025-68664 |
| RAG Knowledge Base | LangChain | CVE-2025-65106, CVE-2025-46059, CVE-2023-46229 |
| Multi-Agent System | CrewAI/LangGraph | CrewAI pentest research, MCPTox benchmark |
| DevOps Automation | LangChain+MCP | CVE-2025-6514, CI/CD pipeline patterns |
| Claude Code | Claude Code (built-in + MCP tools) | OWASP LLM06, OWASP LLM08 (design risk) |
| Jira and Confluence (mcp-atlassian) | MCP | CVE-2026-77260, CVE-2026-77262, CVE-2026-73498, CVE-2026-77253, CVE-2026-77255 |
| Langflow MCP Tools | MCP | CVE-2026-105697, CVE-2025-61260 |
| Claude Code WebFetch | Claude Code | CVE-2026-54316 |

## CVEs Added 2026-11-18

Advisories published from 2026-03-20 to 2026-11-18 for agent and MCP packages, each checked
against its GitHub advisory. The skill CVE database (`ziran/application/skill_cve/`) holds the
full entries. "Agent pair" names the ground-truth agents that model the CVE.

| CVE | Package | Affected | Fixed in | Type | Advisory | Agent pair |
|---|---|---|---|---|---|---|
| CVE-2026-77260 | mcp-atlassian | <0.22.0 | 0.22.0 | path_traversal | [GHSA-f4p7-qx46-wc5j](https://github.com/advisories/GHSA-f4p7-qx46-wc5j) | atlassian_mcp |
| CVE-2026-77248 | mcp-atlassian | <0.22.0 | 0.22.0 | path_traversal | [GHSA-cc5h-2pwp-pvcc](https://github.com/advisories/GHSA-cc5h-2pwp-pvcc) | |
| CVE-2026-77262 | mcp-atlassian | <0.22.0 | 0.22.0 | data_exfiltration | [GHSA-p6hp-93wp-fh6p](https://github.com/advisories/GHSA-p6hp-93wp-fh6p) | atlassian_mcp |
| CVE-2026-77253 | mcp-atlassian | <0.22.0 | 0.22.0 | path_traversal | [GHSA-vc25-24vv-fxxm](https://github.com/advisories/GHSA-vc25-24vv-fxxm) | atlassian_mcp |
| CVE-2026-77246 | mcp-atlassian | <0.22.0 | 0.22.0 | data_exfiltration | [GHSA-wv8v-v4c5-v75j](https://github.com/advisories/GHSA-wv8v-v4c5-v75j) | |
| CVE-2026-73498 | mcp-atlassian | <0.22.0 | 0.22.0 | path_traversal | [GHSA-g5r6-gv6m-f5jv](https://github.com/advisories/GHSA-g5r6-gv6m-f5jv) | atlassian_mcp |
| CVE-2026-77255 | mcp-atlassian | <0.22.0 | 0.22.0 | data_exfiltration | [GHSA-2xj6-xx86-cwwc](https://github.com/advisories/GHSA-2xj6-xx86-cwwc) | atlassian_mcp |
| CVE-2026-116686 | mcp (Python SDK) | >=1.10.0 <1.30.0, >=2.0.0 <2.2.0 | 1.30.0, 2.2.0 | ssrf | [GHSA-rwrf-2pqf-9j8j](https://github.com/advisories/GHSA-rwrf-2pqf-9j8j) | |
| CVE-2026-104850 | @modelcontextprotocol/sdk, /client | >=1.12.0 <1.31.0, >=2.0.0 <2.2.0 | 1.31.0, 2.2.0 | credential_theft | [GHSA-6qxp-vccf-f47h](https://github.com/advisories/GHSA-6qxp-vccf-f47h) | |
| CVE-2026-32871 | fastmcp | <3.2.0 | 3.2.0 | ssrf | [GHSA-vv7q-7jx5-f767](https://github.com/advisories/GHSA-vv7q-7jx5-f767) | |
| CVE-2026-105697 | langflow | >=1.1.2 <1.10.3 | 1.10.3 | command_injection | [GHSA-w794-rj3p-xv45](https://github.com/advisories/GHSA-w794-rj3p-xv45) | langflow_mcp |
| CVE-2025-61260 | @openai/codex | <=0.23.0 | none listed (1) | remote_code_execution | [GHSA-xrxf-jgv3-qmrm](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm) | |
| CVE-2026-54316 | @anthropic-ai/claude-code | >=0.2.54 <2.1.163 | 2.1.163 | data_exfiltration | [GHSA-fg94-h982-f3mm](https://github.com/advisories/GHSA-fg94-h982-f3mm) | claude_code_webfetch |
| CVE-2026-39861 | @anthropic-ai/claude-code | <2.1.64 | 2.1.64 | symlink_bypass | [GHSA-vp62-r36r-9xqp](https://github.com/advisories/GHSA-vp62-r36r-9xqp) | |
| CVE-2026-88968 | @anthropic-ai/claude-code | <2.1.251 | 2.1.251 | symlink_bypass | [GHSA-5xjx-9qx6-jcrv](https://github.com/advisories/GHSA-5xjx-9qx6-jcrv) | |
| CVE-2026-55607 | @anthropic-ai/claude-code | >=2.1.38 <2.1.163 | 2.1.163 | remote_code_execution | [GHSA-7835-87q9-rgvv](https://github.com/advisories/GHSA-7835-87q9-rgvv) | |
| CVE-2026-40068 | @anthropic-ai/claude-code | >=2.1.63 <2.1.84 | 2.1.84 | remote_code_execution | [GHSA-q5hj-mxqh-vv77](https://github.com/advisories/GHSA-q5hj-mxqh-vv77) | |
| CVE-2026-113663 | ag2 | >=0.13.2 <1.1.1 | 1.1.1 | command_injection | [GHSA-2h4w-29cv-2cmv](https://github.com/advisories/GHSA-2h4w-29cv-2cmv) | |
| CVE-2026-7700 | langflow | >=1.3.0 <1.10.3 | 1.10.3 | remote_code_execution | [GHSA-9fpm-3445-2vx4](https://github.com/advisories/GHSA-9fpm-3445-2vx4) | |
| CVE-2026-59207 | n8n | <2.27.4, >=2.28.0 <2.28.1 | 2.27.4, 2.28.1 | credential_theft | [GHSA-h44j-f5r5-ph73](https://github.com/advisories/GHSA-h44j-f5r5-ph73) | |
| CVE-2026-65015 | n8n | <2.29.8, >=2.30.0 <2.30.1 | 2.29.8, 2.30.1 | privilege_escalation | [GHSA-x5vx-c2c8-m3w9](https://github.com/advisories/GHSA-x5vx-c2c8-m3w9) | |
| CVE-2026-86996 | n8n | <2.37.7, >=2.38.0 <2.38.2 | 2.37.7, 2.38.2 | privilege_escalation | [GHSA-7hgx-277f-7vmg](https://github.com/advisories/GHSA-7hgx-277f-7vmg) | |

(1) The advisory lists no patched release. Check Point, the reporter, gives the fix as 0.23.0.

Seeded advisories left out because no agent tool call triggers them: CVE-2026-77243
(mcp-atlassian tool filter bypass by direct JSON-RPC), CVE-2026-59822 (LiteLLM MCP endpoint
authentication bypass), CVE-2026-65589 (n8n credential headers written to execution data) and
CVE-2026-86063 (Claude Code plugin hash-pin bypass at install).

## Labeling Methodology

### True Positive Criteria

A scenario is labeled **true_positive** when ALL of the following hold:

1. The agent configuration contains a **known vulnerability** — either a real CVE from the NVD/GitHub Advisory Database, or a documented design risk from OWASP LLM Top 10
2. The applied attack vector **targets that specific vulnerability**
3. The agent has **no effective mitigations** (no guardrails, no input validation, no tool scoping)
4. The expected outcome is that ZIRAN's detection pipeline **should identify the vulnerability**

### True Negative Criteria

A scenario is labeled **true_negative** when ALL of the following hold:

1. The agent configuration includes **proper mitigations** per the remediation guidance in the corresponding CVE or OWASP reference
2. The same attack vector is applied but **should be blocked** by the mitigations
3. The expected outcome is that ZIRAN's detection pipeline **should NOT flag a vulnerability**

### Source Requirements

Every scenario must be traceable to real-world evidence:

- **Real CVEs**: Verifiable on [NVD](https://nvd.nist.gov/) or [GitHub Advisory Database](https://github.com/advisories)
- **Design risks**: Reference [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) or framework security documentation
- **Published benchmarks**: AgentHarm (ICLR 2025), InjecAgent (ACL 2024), MCPTox (2025), Agent Security Bench (2024)
- **Real incidents**: Documented attacks with public write-ups (e.g., EchoLeak/CVE-2025-32711)

No synthetic or fabricated vulnerability data is used.

### Severity Assignment

Severity follows the source material:
- Real CVEs use their CVSS-derived severity
- Design risks use OWASP severity guidance
- Chain patterns use the risk level from `chain_patterns.yaml`

## Categories

### Tool Chain
Tests the chain analyzer's ability to detect dangerous tool combinations (e.g., `read_file` + `http_request` = data exfiltration). Based on patterns from `chain_patterns.yaml`.

### Side Effect
Tests the side-effect detector's ability to identify dangerous tool invocations (e.g., shell execution, raw SQL, unrestricted email). Based on the tool classifier risk levels.

### Campaign
Tests full multi-phase campaign detection across reconnaissance, trust building, vulnerability discovery, and exploitation. Based on real attack chains combining multiple CVEs.

## Running the Benchmark

```bash
uv run python benchmarks/ground_truth/run.py
```

The benchmark runner evaluates ZIRAN's offline detection components against the labeled dataset and reports precision, recall, and F1 for:

1. **Chain Analyzer** — builds a knowledge graph from each agent's tools and checks if expected dangerous chains are discovered
2. **Skill CVE Matcher** — runs `SkillCVEDatabase.check_agent()` and compares matches to known vulnerabilities
3. **Tool Classifier** — classifies each tool's risk tier and compares to declared risk levels
4. **Scenario Verdict** — combines chain analysis and CVE matching to predict TP/TN at the scenario level

## Validation

```bash
uv run python benchmarks/ground_truth/validate.py
```

The validation script:
1. Loads all YAML files and validates against Pydantic schema
2. Cross-references CVE IDs against the `SkillCVEDatabase`
3. Verifies agent references are valid
4. Reports coverage statistics by category and detector
