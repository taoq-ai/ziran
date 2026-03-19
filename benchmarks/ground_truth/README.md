# Ground Truth Dataset for Accuracy Measurement

A labeled dataset of 54 scenarios (29 true-positive, 25 true-negative) for measuring ZIRAN's detection precision, recall, and F1 score.

## Dataset Structure

```
ground_truth/
    agents/                    # 14 agent definitions (7 vulnerable + 7 safe)
    scenarios/
        tool_chain/            # 18 scenarios (10 TP, 8 TN)
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
