# Interpreting Results

How to read and act on ZIRAN scan results.

## Report Formats

### HTML Report (Recommended)

The interactive HTML report includes:

- **Campaign summary** — Overall metrics and status
- **Knowledge graph** — Interactive visualization of agent capabilities and attack paths
- **Phase timeline** — Results from each scan phase
- **Dangerous tool chains** — Highlighted with risk levels and remediation

### Markdown Report

A clean text-based summary suitable for CI/CD pipelines and code reviews.

### JSON Report

Machine-parseable output for programmatic analysis and integration with other tools.

## Understanding Severity

| Level | Meaning | Action |
|-------|---------|--------|
| **Critical** | Immediate exploitation possible; data loss or RCE | Fix immediately |
| **High** | Significant risk; exploitation likely with effort | Fix before production |
| **Medium** | Moderate risk; requires specific conditions | Plan remediation |
| **Low** | Minor risk; informational | Monitor |

## Tool Chain Findings

Tool chain findings are unique to ZIRAN. They represent **dangerous combinations** of tools, not individual vulnerabilities.

Example: `read_file → http_request` (Critical: Data Exfiltration)

**What this means:** An attacker who achieves prompt injection can instruct the agent to read local files and send their contents to an external server.

**How to fix:** See the `remediation` field in each chain finding. Common fixes include:
- Restricting tool access (principle of least privilege)
- Adding URL allowlists for network tools
- Sandboxing file system access
- Requiring confirmation for sensitive operations

## Acting on Results

1. **Fix critical and high findings first** — These represent real, exploitable vulnerabilities
2. **Review tool chains** — Even if no prompt injection was found, dangerous tool combinations are a latent risk
3. **Check Skill CVEs** — Cross-reference findings with known CVEs in your agent's tools
4. **Re-scan after fixes** — Verify that remediations are effective
