# MITRE ATLAS Mapping

ZIRAN maps every attack vector in its library to one or more [MITRE ATLAS](https://atlas.mitre.org/) techniques. This page explains how the mapping works, where the data comes from, and how to read it in reports and dashboards.

!!! info "Snapshot"
    The ATLAS taxonomy embedded in ZIRAN is **pinned to the October 2025 ATLAS release** (16 tactics, 86 techniques, 14 AI-agent-specific techniques). Later ATLAS updates are adopted by later ZIRAN releases. This mirrors how OWASP LLM Top 10 is already embedded.

## Why ATLAS

OWASP LLM Top 10 is the dominant taxonomy for LLM application security, and ZIRAN has mapped to it since v0.22. ATLAS is the MITRE-maintained equivalent for **adversarial AI threats** — tactics, techniques, mitigations — and it's what red-team and threat-intelligence teams use when they align AI-security findings with the rest of their threat model.

Adding ATLAS as a second mapping (not replacing OWASP) lets ZIRAN serve both audiences without duplicating effort:

- Compliance teams see `LLM01`, `LLM02`, … next to each finding.
- Red-team / threat-intel teams see `AML.T0051`, `AML.T0054`, … next to the same finding.

## Where the taxonomy lives

ZIRAN embeds the ATLAS taxonomy as enums and dicts in [`ziran/domain/entities/attack.py`](https://github.com/taoq-ai/ziran/blob/main/ziran/domain/entities/attack.py), mirroring how `OwaspLlmCategory` and `OWASP_LLM_DESCRIPTIONS` are stored:

| Symbol | Purpose |
|---|---|
| `AtlasTactic` | 16-value `StrEnum` of tactics (`AML.TA0000` … `AML.TA0015`). |
| `AtlasTechnique` | `StrEnum` of every technique referenced by at least one vector plus all 14 agent-specific techniques. |
| `ATLAS_TACTIC_DESCRIPTIONS` | Human-readable name per tactic. |
| `ATLAS_TECHNIQUE_DESCRIPTIONS` | Human-readable name per technique. |
| `ATLAS_TECHNIQUE_TO_TACTIC` | Canonical parent tactic(s) for each technique (list-valued — some techniques legitimately span multiple tactics in the ATLAS data). |
| `AGENT_SPECIFIC_TECHNIQUES` | The 14 agent-focused techniques from the October 2025 ATLAS release, highlighted on the coverage dashboard. |

## How vectors are annotated

Each attack-vector YAML file under [`ziran/application/attacks/vectors/`](https://github.com/taoq-ai/ziran/tree/main/ziran/application/attacks/vectors) carries an `atlas_mapping` list on every vector:

```yaml
- id: pi_basic_override
  name: Basic Instruction Override
  category: prompt_injection
  # ...
  owasp_mapping: [LLM01]
  atlas_mapping: [AML.T0051, AML.T0051.000, AML.T0054, AML.T0065]
```

Multi-value mappings are normal — an attack often exercises more than one ATLAS technique at once (e.g., direct prompt injection + prompt crafting + jailbreak).

A CI gate (`benchmarks/atlas_coverage.py`) ensures every vector on `main` has a non-empty `atlas_mapping`. If you add a new YAML vector without one, CI fails.

## How it shows up

### CLI

Filter the library by ATLAS technique ID, just like `--owasp`:

```bash
ziran library --atlas AML.T0051        # LLM Prompt Injection
ziran library --atlas AML.T0070        # RAG Poisoning
ziran library --atlas AML.T0054        # LLM Jailbreak
```

Invalid IDs get a `difflib` close-match suggestion:

```text
Error: Unknown ATLAS technique 'AML.T00051'. Did you mean: AML.T0051, AML.T0053, AML.T0054?
```

The `library` table also includes an **ATLAS** column alongside the existing **OWASP** column.

### Campaign reports

Both Markdown and HTML reports include a **MITRE ATLAS Coverage** section, grouped by tactic, with agent-specific techniques marked `🎯`:

```markdown
| Tactic                         | Technique                  | Status  | Findings |
|--------------------------------|----------------------------|---------|----------|
| AML.TA0005 (Execution)         | AML.T0051 — LLM Prompt Injection 🎯 | 🔴 FAIL | 12 vulns |
| AML.TA0012 (Privilege Escalation) | AML.T0054 — LLM Jailbreak 🎯      | 🔴 FAIL | 3 vulns  |
```

The JSON report exposes `atlas_mapping` on each finding natively.

### Benchmark dashboard

`benchmarks/atlas_coverage.py` generates a coverage summary:

```bash
uv run python benchmarks/atlas_coverage.py
# or
uv run python benchmarks/atlas_coverage.py --json benchmarks/results/atlas_coverage.json
```

The script exits non-zero when:

- Any vector on `main` lacks an `atlas_mapping` (CI gate),
- Not all 14 agent-specific techniques are covered,
- Under `--strict`, fewer than 60 techniques are represented.

JSON output is deterministic (stable key + array ordering, no timestamps) so downstream signing workflows like [asqav](https://github.com/taoq-ai/ziran/issues/259) can hash it.

## Coverage scope (honest)

ZIRAN's library does not cover **every** ATLAS tactic uniformly. Two tactics have limited coverage by design:

| Tactic | ZIRAN coverage | Why |
|---|---|---|
| `AML.TA0000` AI Model Access | Partial | ZIRAN tests *through* the inference API rather than attempting to acquire AI model access as an adversary goal. |
| `AML.TA0001` AI Attack Staging | Partial | ZIRAN *executes* adversarial attacks; it is not an attacker's staging workflow. |

See issue [#264](https://github.com/taoq-ai/ziran/issues/264) for the follow-up work that extends coverage into these two tactics via dedicated reconnaissance and staging vectors.

## Updating the snapshot

When MITRE publishes a new ATLAS release:

1. Pull the updated `ATLAS.yaml` from the upstream [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) repo.
2. Update the `AtlasTechnique` enum and the three dicts in [`ziran/domain/entities/attack.py`](https://github.com/taoq-ai/ziran/blob/main/ziran/domain/entities/attack.py).
3. Bump the `_SNAPSHOT_DATE` constant at the top of [`benchmarks/atlas_coverage.py`](https://github.com/taoq-ai/ziran/blob/main/benchmarks/atlas_coverage.py).
4. Re-annotate any vectors affected by rename/deprecation.
5. Run `benchmarks/generate_all.py` and commit the regenerated artefacts.

`AGENT_SPECIFIC_TECHNIQUES` should be updated only when MITRE publishes a new agent-specific designation.

## References

- [MITRE ATLAS matrix](https://atlas.mitre.org/matrices/ATLAS)
- [`mitre-atlas/atlas-data` on GitHub](https://github.com/mitre-atlas/atlas-data)
- ZIRAN spec: [`specs/012-benchmark-maturity/spec.md`](https://github.com/taoq-ai/ziran/blob/main/specs/012-benchmark-maturity/spec.md)
- Flagship retro-mapping PR: [#263](https://github.com/taoq-ai/ziran/pull/263)
