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

## Suppressing Accepted Findings

A finding your team has reviewed and accepted can be recorded in a committed file so the
gate stops failing on it, while any change to that finding fails the gate again.

`ziran ci` loads `.ziran/suppressions.yaml` from the working directory when it exists.
Pass `--suppressions PATH` to use another file. A file that cannot be read or validated
stops the run with `Error loading suppressions: ...` and exit code 1. A path given to
`--suppressions` that does not exist is a usage error (exit code 2).

```yaml
# .ziran/suppressions.yaml
version: 1
entries:
  - fingerprint: a8fe72c13edad12d1df1d032a83ebe7a5b0320e125cfc28de5321a0421117f6e
    content_hash: c80a79447eb700e60463275c8d4d21da825727c816ab30ad956303ae64133eae
    reason: "Prompt-injection echo accepted: output is sandboxed (SEC-123)"
    added_by: security-team
    expires: 2026-12-31   # optional; the entry is valid through this date
```

`fingerprint` and `content_hash` are 64-character lowercase hex values printed by `ziran ci`.
`reason` and `added_by` are required. Unknown keys are rejected.

### Fingerprint and content hash

Each finding the gate counts gets two values:

- **fingerprint**: what the finding is. For a successful attack it is the target agent, the
  vector id and the category (the same fingerprint the web UI findings page uses). For a
  dangerous tool chain it is the target agent and the vulnerability type.
- **content hash**: what the finding contains. For an attack it covers the severity and the
  category. For a chain it covers the tools, in order, and the risk level.

Evidence (including `tool_calls`), agent responses, prompts and names are never hashed, because
they change between runs.

| What changed since the entry was written | State | Gate |
|---|---|---|
| Nothing material (only evidence, response, prompt or name) | suppressed | not counted |
| Attack severity, chain tools or chain risk level | regressed | counted, plus a `suppression_regressed` violation |
| Attack category, vector id, chain vulnerability type or target agent | new | counted |

The severity thresholds and `max_critical_findings` count only new and regressed findings.
A `suppression_regressed` violation names the entry's fingerprint and the new content hash.
Several chains with the same vulnerability type share one fingerprint; add one entry per
accepted content hash.

### Expiry

An entry with `expires` in the past no longer suppresses anything, and each such entry adds a
`suppression_expired` violation (whether or not it still matches a finding). Renew the date
or remove the entry.

### Policy rule with a suppressions file

Without a file, `fail_on_policy_violation` fails whenever the result is marked vulnerable.
With a file, `policy_violation` fires only if at least one of these holds:

1. a finding is not suppressed;
2. a critical attack path ends at a node that is not backed by a suppressed finding (the
   vector id of a suppressed attack, or the composition node of a suppressed chain);
3. a phase reported a vulnerability id that is not backed in the same way.

Critical paths that end at a data-source node (such as `sensitive_data`) can never be backed,
so such results still fail `policy_violation` even with every finding suppressed. If that is
acceptable for your agent, set `fail_on_policy_violation: false` in the gate config; the
severity thresholds still apply. With a file loaded, the rule is also stricter than before in
one case: any unsuppressed finding fails it, including a non-critical chain.

### Bootstrapping the file

Fingerprints are printed only when a suppressions file is loaded. Start with an empty file:

```yaml
version: 1
entries: []
```

Then run the gate and copy the printed values into entries for the findings you accept.
Output from a scan result with two successful attacks, one critical chain and one critical path:

```text
Unsuppressed findings (copy fingerprint/content_hash into the suppressions file to accept):
  new attack v1 [critical] fingerprint=a8fe72c13edad12d1df1d032a83ebe7a5b0320e125cfc28de5321a0421117f6e content_hash=c80a79447eb700e60463275c8d4d21da825727c816ab30ad956303ae64133eae
  new attack v2 [medium] fingerprint=c3b1e7f24e5b6f3695e4e53156dd95d62eff493db6db541352c4ae532905812e content_hash=4d94a27a271448b34308f94a1a936f35250691b0b6aaf611d99b667882fd7eef
  new chain data_exfiltration [critical] fingerprint=64e139a4957bcaaff763cacd45656f8a63a14d6460be47291ba6f443d92d868f content_hash=652b01e461d943c024616e2cfbf55b5126ecd04fd30cec0d3cd456fcea867b7e
```

With all three accepted, the same result passes:

```text
│ PASSED  Trust: 0.30  |  Findings: 0 (C:0 H:0 M:0 L:0)  |  New: 0  Suppressed: 3  Regressed: 0 │
```

### Outputs

When a file is loaded:

- the summary line ends with `| Suppressions: new N, suppressed S, regressed R`;
- `$GITHUB_OUTPUT` gets `new_findings`, `suppressed_findings` and `regressed_findings`
  (the composite GitHub Action does not re-export these yet; it does auto-load the file,
  since it runs `ziran ci` in the workspace root);
- the step summary gets a `### Suppressions` table, and suppressed attacks are left out of
  "Vulnerabilities Found";
- no annotation is emitted for a suppressed attack;
- in SARIF, a suppressed attack result carries
  `"suppressions": [{"kind": "external", "justification": "<reason>"}]`.

Without a file, all outputs are unchanged.

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
