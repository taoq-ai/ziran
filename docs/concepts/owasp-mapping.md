# OWASP Top 10 for LLM Applications

ZIRAN maps every attack vector and finding to the **OWASP Top 10 for Large Language Model Applications** — the industry-standard risk taxonomy for AI systems.

## What is OWASP LLM Top 10?

The [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) identifies the most critical security risks for applications built on large language models. ZIRAN uses it as the organizing framework for its attack library and reports.

## Coverage Matrix

| Code | Category | ZIRAN Vectors | Coverage |
|------|----------|---------------|----------|
| **LLM01** | Prompt Injection | 52 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 20 | :white_check_mark: Strong |
| **LLM03** | Training Data Poisoning | 15 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | — | :construction: Planned |
| **LLM05** | Supply Chain Vulnerabilities | — | :construction: Planned |
| **LLM06** | Sensitive Information Disclosure | 51 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 20 | :white_check_mark: Strong |
| **LLM08** | Excessive Agency | 18 | :white_check_mark: Strong |
| **LLM09** | Overreliance | 15 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | — | :construction: Planned |

!!! info "Coverage contributions welcome"

    LLM04, LLM05, and LLM10 are on the roadmap. PRs adding vectors for these categories are welcome — see [Contributing](../community/contributing.md).

## Category Details

### LLM01: Prompt Injection (52 vectors)

Manipulating the LLM through crafted inputs to override system instructions. ZIRAN tests both **direct injection** (user input) and **indirect injection** (via external data sources like documents, search results, and RAG contexts).

**ZIRAN approach:** Multi-phase trust exploitation builds conversational context before injecting, defeating simple guardrails.

### LLM02: Insecure Output Handling (20 vectors)

When LLM output is consumed by downstream systems without sanitization. ZIRAN tests for outputs that contain executable code, SQL, or markup that could be interpreted by downstream consumers.

**ZIRAN approach:** Tool chain analysis identifies output paths where unsanitized content flows to dangerous consumers (databases, file systems, APIs).

### LLM03: Training Data Poisoning (15 vectors)

Testing whether the agent's responses reveal poisoned training data or can be manipulated through memory poisoning in long-running sessions.

**ZIRAN approach:** Memory poisoning vectors plant instructions that persist across conversation turns.

### LLM06: Sensitive Information Disclosure (51 vectors)

Extracting confidential data — system prompts, API keys, PII, database contents — through the LLM's tools and outputs.

**ZIRAN approach:** System prompt extraction, data exfiltration via tool chains, PII leakage through conversation manipulation.

### LLM07: Insecure Plugin Design (20 vectors)

Exploiting tools/plugins with insufficient access controls, missing input validation, or overly broad permissions.

**ZIRAN approach:** Tool manipulation vectors test each discovered tool with malicious parameters. Static analysis checks for missing input validation (SA002) and overly broad tool access (SA004).

### LLM08: Excessive Agency (18 vectors)

When agents have more permissions, tools, or autonomy than necessary for their intended purpose.

**ZIRAN approach:** Privilege escalation vectors attempt to access capabilities beyond the agent's declared scope. Tool chain analysis flags unnecessarily dangerous tool combinations.

### LLM09: Overreliance (15 vectors)

Testing whether agents can be tricked into making decisions or taking actions based on incorrect or manipulated information.

**ZIRAN approach:** Chain-of-thought manipulation vectors hijack the agent's reasoning to alter tool selection and execution.

## Using OWASP in Reports

### Filter by OWASP Category

```bash
# List vectors for a specific category
ziran library --owasp LLM01

# Require OWASP coverage in CI
ziran ci results.json --gate-config gate.yaml
```

### Quality Gate Configuration

```yaml
# gate.yaml
require_owasp_coverage:
  - LLM01
  - LLM06
  - LLM07
```

### Policy Rules

```yaml
# policy.yaml
rules:
  - rule_type: required_owasp
    description: Must test all high-priority OWASP categories
    severity: high
    parameters:
      categories: [LLM01, LLM06, LLM07, LLM08]
```

### In HTML Reports

The HTML report includes an OWASP coverage section that maps findings to categories, showing:

- Which categories were tested
- Number of findings per category
- Pass/fail status per category
- Links to OWASP documentation

## See Also

- [Attack Vectors](attack-vectors.md) — Full vector inventory
- [Quality Gate](../guides/cicd-integration.md) — Enforcing OWASP coverage in CI/CD
