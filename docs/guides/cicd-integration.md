# CI/CD Integration

ZIRAN integrates into your CI/CD pipeline to **block insecure agents from reaching production**. It provides quality gates, policy enforcement, SARIF output, and GitHub Actions annotations.

## GitHub Action

Add ZIRAN to any GitHub Actions workflow:

```yaml
# .github/workflows/security.yml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ZIRAN scan
        uses: taoq-ai/ziran@v0
        with:
          target: target.yaml
          coverage: standard
          sarif: results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

This runs a scan on every push and PR, uploads findings to GitHub's Security tab, and fails the build if critical vulnerabilities are found.

## Quality Gate

The quality gate evaluates scan results against configurable thresholds:

```bash
ziran ci results.json --gate-config gate.yaml
```

### Gate Configuration

```yaml
# gate.yaml
min_trust_score: 0.7              # Minimum trust score (0.0-1.0)
max_critical_findings: 0          # Zero tolerance for critical
fail_on_policy_violation: true    # Fail if policy rules violated

severity_thresholds:
  critical: 0     # Max allowed critical findings
  high: 3         # Max allowed high findings
  medium: 10      # Max allowed medium findings
  low: -1         # Unlimited low findings (-1)

require_owasp_coverage:           # Required OWASP categories
  - LLM01
  - LLM06
  - LLM07
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Gate passed — safe to deploy |
| 1 | Gate failed — vulnerabilities exceed thresholds |
| 2 | Configuration error |

## Policy Engine

For more complex compliance rules, use the policy engine:

```bash
ziran policy results.json --policy policy.yaml
```

### Policy Configuration

```yaml
# policy.yaml
id: production-policy
name: Production Security Policy
version: "1.0"
description: Minimum security requirements for production agents

rules:
  - rule_type: min_trust_score
    description: Agent must achieve minimum trust score
    severity: critical
    parameters:
      threshold: 0.7

  - rule_type: max_critical_vulnerabilities
    description: No critical vulnerabilities allowed
    severity: critical
    parameters:
      threshold: 0

  - rule_type: max_high_vulnerabilities
    description: Limited high-severity findings
    severity: high
    parameters:
      threshold: 5

  - rule_type: required_owasp
    description: Must test high-priority OWASP categories
    severity: high
    parameters:
      categories: [LLM01, LLM06, LLM07, LLM08]

  - rule_type: max_critical_paths
    description: No critical tool chain paths
    severity: critical
    parameters:
      threshold: 0

  - rule_type: forbidden_findings
    description: Block specific finding types
    severity: critical
    parameters:
      finding_ids: [system_prompt_leaked, credentials_exposed]
```

### Available Rule Types

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `min_trust_score` | Minimum overall trust score | `threshold` (0.0–1.0) |
| `max_critical_vulnerabilities` | Max critical findings | `threshold` (int) |
| `max_high_vulnerabilities` | Max high findings | `threshold` (int) |
| `max_total_vulnerabilities` | Max total findings | `threshold` (int) |
| `required_categories` | Attack categories that must be tested | `categories` (list) |
| `required_owasp` | OWASP categories that must be tested | `categories` (list) |
| `forbidden_findings` | Specific findings that fail the gate | `finding_ids` (list) |
| `max_critical_paths` | Max dangerous tool chain paths | `threshold` (int) |

## SARIF Output

Generate [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) reports for integration with GitHub Security, Azure DevOps, and other code scanning tools:

```bash
ziran ci results.json --sarif results.sarif
```

Upload to GitHub's Security tab:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear as security alerts with:

- Severity level
- OWASP category mapping
- Remediation guidance
- Link to attack vector documentation

## GitHub Actions Features

### Annotations

ZIRAN emits GitHub Actions annotations for findings:

```bash
ziran ci results.json --github-annotations
```

This places warning/error annotations directly on PR diffs.

### Step Summary

```bash
ziran ci results.json --github-summary
```

Writes a Markdown summary to `$GITHUB_STEP_SUMMARY` showing:

- Pass/fail status
- Trust score
- Finding counts by severity
- Top tool chain risks

## Full Pipeline Example

```yaml
name: Agent Security
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install ZIRAN
        run: pip install ziran[all]

      - name: Run scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          ziran scan --target target.yaml \
            --coverage standard \
            --output results/

      - name: Quality gate
        run: |
          ziran ci results/campaign_*_report.json \
            --gate-config gate.yaml \
            --policy policy.yaml \
            --sarif results.sarif \
            --github-annotations \
            --github-summary

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## See Also

- [Quality Gate Config Reference](../reference/cli.md) — CLI flags for `ziran ci`
- [Policy Engine](../concepts/owasp-mapping.md) — OWASP-based policy rules
