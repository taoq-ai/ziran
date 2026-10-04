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

`AML.TA0000` AI Model Access and `AML.TA0001` AI Attack Staging describe adversary activities (getting access to a model, preparing an attack) rather than outcomes on a target, so their coverage needs a note. The numbers below come from `uv run python benchmarks/atlas_coverage.py --json`; the script is the source of truth and the figures will drift as vectors are added.

| Tactic | Technique | Vectors | Basis |
|---|---|---:|---|
| `AML.TA0000` AI Model Access (3/4) | `AML.T0040` AI Model Inference API Access | 468 | Premise of every scan (see below) |
| | `AML.T0047` AI-Enabled Product or Service | 457 | Premise of every scan (see below) |
| | `AML.T0044` Full AI Model Access | 2 | Model-theft vectors (`mt_systematic_extraction`, `mt_deterministic_weight_approximation`) |
| | `AML.T0041` Physical Environment Access | 0 | Out of scope: ZIRAN tests software agents over their APIs and has no physical access to the deployment |
| `AML.TA0001` AI Attack Staging (7/7) | `AML.T0042` Verify Attack | 384 | Prompt-injection, indirect-injection, tool-manipulation, MCP, A2A and harmful-task vectors that check whether the attack landed |
| | `AML.T0043` Craft Adversarial Data | 175 | Prompt-injection, jailbreak, harmful-task, MCP and A2A vectors (the payload is the crafted adversarial data) |
| | `AML.T0018` Manipulate AI Model (and `.000` / `.001` / `.002`) | 19 / 17 / 17 / 13 | Memory-poisoning, supply-chain, A2A and multi-turn vectors; shared with `AML.TA0006` Persistence |
| | `AML.T0005` Create Proxy AI Model | 1 | Model extraction (`mt_systematic_extraction`) |

`AML.T0040` and `AML.T0047` coverage comes from the premise that every ZIRAN scan reaches the target through its inference API, inside an AI-enabled product or service. It is not a separate model-access attack, so read these two counts as context, not as a distinct capability.

The per-tactic vector totals printed by the script add up per-technique counts, so a vector tagged with several techniques counts once per technique (`AML.TA0000` shows 927 for a 661-vector library); the table above therefore lists techniques.

No dedicated staging or reconnaissance vectors are added for AI Attack Staging: adversary-side staging has no observable outcome on a target, and tagging vectors with it would only pad counts.

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
