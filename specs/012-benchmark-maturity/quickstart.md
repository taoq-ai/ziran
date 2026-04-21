# Quickstart: Benchmark Maturity

**Feature**: 012-benchmark-maturity

Short end-user walkthroughs that validate each acceptance signal in `spec.md` using only commands that exist after this release.

## 1. Find the ATLAS technique for an existing vector

```text
$ ziran library --filter pi_basic_override
  ID                  Name                        Severity  OWASP    ATLAS
  ─────────────────────────────────────────────────────────────────────────
  pi_basic_override   Basic system prompt override  high    LLM01    AML.T0051
```

One line, one ATLAS technique, one OWASP category — matches Acceptance Scenario 1.1.

## 2. List all vectors for a specific ATLAS technique

```text
$ ziran library --atlas AML.T0051
```

Matches US1 Scenario 1.2.

## 3. Confirm OWASP 10/10

```text
$ uv run python benchmarks/owasp_coverage.py
Category     Vectors   Status
LLM01        434       comprehensive
LLM02        194       comprehensive
LLM03        15        strong
LLM04        12        strong
LLM05        11        strong           ← was: moderate
LLM06        95        comprehensive
LLM07        136       comprehensive
LLM08        139       comprehensive
LLM09        15        strong
LLM10        12        strong           ← was: not covered
```

Matches US2 Scenario 2.1.

## 4. Generate the ATLAS coverage report

```text
$ uv run python benchmarks/atlas_coverage.py
Techniques covered: 63/66
Agent-specific techniques covered: 14/14  ✓
Uncovered techniques: AML.T0040, AML.T0041, AML.T0042

$ uv run python benchmarks/atlas_coverage.py --json benchmarks/results/atlas_coverage.json
Written benchmarks/results/atlas_coverage.json
```

Matches US1 Scenario 1.3.

## 5. Run a campaign and inspect the ATLAS section in the report

```text
$ ziran scan --target examples/01-langchain-agent/agent.py --report-format markdown
Report written to reports/latest.md

$ head -40 reports/latest.md
# Campaign Report
…
## Findings (12)

### Finding 1: pi_basic_override
- OWASP: LLM01 (Prompt Injection)
- ATLAS: AML.T0051 (LLM Prompt Injection) — Tactic: Initial Access
- Severity: high
- Evidence: …

…

## ATLAS Coverage Summary
| Tactic              | Findings | Techniques   |
|---------------------|----------|--------------|
| Initial Access      | 8        | AML.T0051, AML.T0052 |
| Persistence         | 2        | AML.T0070    |
| …                   | …        | …            |
```

Matches US1 Scenario 1.1 and SC-004.

## 6. Run a RAG-poisoning focused campaign

```text
$ ziran library --tag rag-poisoning
  ID                         Name                             OWASP    ATLAS
  ─────────────────────────────────────────────────────────────────────────────
  rag_credential_doc         Credential-leak doc framing      LLM01    AML.T0070
  rag_policy_override_email  Email-framed policy override     LLM01    AML.T0051
  …

$ ziran scan --target <rag-agent> --include-tag rag-poisoning
```

Matches US4 Scenario 4.1 and 4.2.

## 7. Run a campaign with a defence profile

Create `profiles/prod-ingress.yaml`:

```yaml
name: prod-ingress-v1
defences:
  - kind: input_filter
    identifier: nemo-guardrails@v0.8
    evaluable: false
  - kind: output_guard
    identifier: lakera-guard@2025-09
    evaluable: false
```

Run:

```text
$ ziran scan --target <agent> --defence-profile profiles/prod-ingress.yaml
```

Report contains:

```markdown
## Declared Defences

| Kind          | Identifier                    | Evaluable |
|---------------|-------------------------------|-----------|
| input_filter  | nemo-guardrails@v0.8          | no        |
| output_guard  | lakera-guard@2025-09          | no        |

Evasion rate: not computable (no declared defence is evaluable in this release).
```

And a campaign run without `--defence-profile`:

```text
$ ziran scan --target <agent>
```

Produces a report that contains **zero** defence or evasion content — byte-identical to pre-release reports for the same target. Matches US5 Scenarios 5.1 and 5.2.

## 8. Validate determinism

Run the benchmark regeneration twice:

```text
$ uv run python benchmarks/generate_all.py
$ sha256sum benchmarks/results/*.json > /tmp/hashes_a
$ uv run python benchmarks/generate_all.py
$ sha256sum benchmarks/results/*.json > /tmp/hashes_b
$ diff /tmp/hashes_a /tmp/hashes_b
# empty — byte-identical
```

Matches SC-006.

## 9. Quality gates

Standard constitution gates on the final PR:

```text
$ uv run ruff check .
$ uv run ruff format --check .
$ uv run mypy ziran/
$ uv run pytest --cov=ziran
  …
  TOTAL    90%   PASSED
```

All clean — required to close the milestone.
