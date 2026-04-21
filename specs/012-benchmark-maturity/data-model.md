# Phase 1 Data Model: Benchmark Maturity

**Feature**: 012-benchmark-maturity
**Date**: 2026-04-21
**Depends on**: [research.md](./research.md)

## Scope

This release adds one new threat-framework taxonomy (MITRE ATLAS), one new campaign-config entity (DefenceProfile), one new campaign-level metric (EvasionRate), and extends two existing entities (AttackVector and AttackResult) with a new mapping field. It does not introduce any new database schemas or persistent storage — all data is in-memory, YAML-loaded, or emitted in report artefacts.

## Entities

### AtlasTactic *(new enum)*

| Field | Type | Notes |
|---|---|---|
| value | `str` | Canonical ATLAS tactic ID (e.g., `"AML.TA0002"`). |

- **Shape**: `StrEnum` in `ziran/domain/entities/attack.py`.
- **Cardinality**: 15 values at the October 2025 snapshot date.
- **Invariants**:
  - Value format matches `^AML\.TA\d{4}$`.
  - Every tactic listed in the library's `ATLAS_TECHNIQUE_TO_TACTIC` codomain exists in this enum.

### AtlasTechnique *(new enum)*

| Field | Type | Notes |
|---|---|---|
| value | `str` | Canonical ATLAS technique ID (e.g., `"AML.T0051"` or sub-technique like `"AML.T0051.001"`). |

- **Shape**: `StrEnum` in `ziran/domain/entities/attack.py`.
- **Cardinality**: Initially populated with every technique referenced by at least one vector in the library. Target ≥ 60 distinct techniques after Phase 3. All 14 October-2025 AI-agent-specific techniques are included regardless of whether a vector references them (enables coverage-gap reporting).
- **Invariants**:
  - Value format matches `^AML\.T\d{4}(\.\d{3})?$`.
  - Every technique value is a key in `ATLAS_TECHNIQUE_DESCRIPTIONS` and `ATLAS_TECHNIQUE_TO_TACTIC`.

### Module-level ATLAS constants *(new)*

- `ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str]` — human-readable technique name.
- `ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, AtlasTactic]` — canonical parent tactic for each technique.
- `AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique]` — the 14 AI-agent-specific techniques added in the October 2025 ATLAS release. Used by the benchmark dashboard to highlight agent-focused coverage.

All three constants live next to `OWASP_LLM_DESCRIPTIONS` for discoverability.

### AttackVector *(extended)*

New field only. Existing fields unchanged.

| Field | Type | Default | Notes |
|---|---|---|---|
| `atlas_mapping` | `list[AtlasTechnique]` | `[]` | Zero or more ATLAS techniques this vector exercises. Populated via YAML. After Phase 3, enforced non-empty by CI lint. |

- **YAML contract**: see [contracts/attack-vector-yaml.md](./contracts/attack-vector-yaml.md).
- **Backwards compatibility**: default-empty list ensures existing YAML files load without modification. Existing consumers of `AttackVector` see the new field via `model_dump`; it's omitted from JSON when empty if `exclude_none=True` is not set (current reports include empty lists; after Phase 3 no vector should have an empty list in `main`).

### AttackResult *(extended)*

New field only. Mirrors `AttackVector`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `atlas_mapping` | `list[AtlasTechnique]` | `[]` | Copied from the executing vector at attack-dispatch time. |

- **Population**: the existing dispatch path that copies `owasp_mapping` from vector to result is extended to copy `atlas_mapping` too.

### DefenceProfile *(new entity)*

New Pydantic model. Used at campaign-config time and echoed into `CampaignResult`.

| Field | Type | Notes |
|---|---|---|
| `name` | `str` | Free-form profile label (e.g., `"prod-ingress-v1"`). |
| `defences` | `list[DefenceDeclaration]` | Zero or more defence declarations. Empty list semantically equivalent to no profile (FR-017). |

**Module location**: `ziran/domain/entities/campaign.py` (or a new sibling module `defence.py` if the file grows).

### DefenceDeclaration *(new entity)*

| Field | Type | Notes |
|---|---|---|
| `kind` | `Literal["input_filter", "output_guard", "hybrid"]` | What family of defence this is. |
| `identifier` | `str` | Free-form; typically `<product>@<version>` (e.g., `"nemo-guardrails@v0.8"`). |
| `evaluable` | `bool` | `True` only when ZIRAN knows how to test whether an attack bypasses this defence. Always `False` in this release (future integrations flip this per supported product). |

- **Invariants**: `kind` is one of the three literals; `identifier` non-empty; `evaluable` defaults to `False`.

### CampaignResult *(extended)*

Two new optional fields. Existing fields unchanged.

| Field | Type | Default | Notes |
|---|---|---|---|
| `defence_profile` | `DefenceProfile \| None` | `None` | Echo of the profile supplied at campaign config; omitted from JSON when `None`. |
| `evasion_rate` | `float \| None` | `None` | Proportion [0.0, 1.0] of attacks that succeeded despite evaluable declared defences. `None` when no profile, empty profile, or no evaluable defences. Omitted from JSON when `None`. |

- **Serialisation**: `model_dump(exclude_none=True)` preserves byte-identity with pre-release outputs whenever no profile is declared. Mandatory for deterministic-output guarantee (FR-020) and downstream signing.

### EvasionMetric *(computation, not a persisted entity)*

- **Location**: `ziran/application/campaign/evasion.py`.
- **Signature**:

  ```python
  def compute_evasion_rate(
      findings: Sequence[AttackResult],
      profile: DefenceProfile | None,
  ) -> float | None
  ```

- **Behaviour**:
  - `profile is None` → `None`.
  - `profile.defences == []` → `None` (empty = absent per FR-017).
  - No defence in the profile has `evaluable=True` → `None` (report surfaces "declared but not computable").
  - Otherwise → `bypassed / total_attempted`, where `bypassed` counts findings that succeeded AND bypassed evaluable defences. In this release that's structurally always zero; future evaluator integrations populate a per-finding bypass flag from which this is computed.
- **Pure function**: no I/O, no mutation.

## Relationships

```text
AttackVector  ──(has-many)──▶  AtlasTechnique
AttackVector  ──(has-many)──▶  OwaspLlmCategory         (existing)

AttackResult  ──(has-many)──▶  AtlasTechnique           (copied from vector at dispatch)
AttackResult  ──(has-many)──▶  OwaspLlmCategory         (existing)

AtlasTechnique  ──(belongs-to-1)──▶  AtlasTactic        (via ATLAS_TECHNIQUE_TO_TACTIC)

CampaignResult  ──(has-optional-1)──▶  DefenceProfile
DefenceProfile  ──(has-many)──▶  DefenceDeclaration

CampaignResult  ──(has-optional-scalar)──▶  evasion_rate (float | None)
```

## State transitions

None of the new entities have lifecycle states. `CampaignResult` transitions are unchanged; the new fields are populated once at campaign finalisation and never mutated thereafter.

## Validation rules summary

| Rule | Where enforced |
|---|---|
| `atlas_mapping` members must all be valid `AtlasTechnique` | Pydantic validation on model load |
| Every vector in `main` has non-empty `atlas_mapping` | CI lint (after Phase 3) — `lint_atlas_coverage()` returns empty list |
| Every `AtlasTechnique` enum value appears in `ATLAS_TECHNIQUE_DESCRIPTIONS` and `ATLAS_TECHNIQUE_TO_TACTIC` | Unit test on enum completeness |
| `AGENT_SPECIFIC_TECHNIQUES` has exactly 14 entries | Unit test |
| `DefenceProfile.defences == []` ⇒ `evasion_rate is None` | Unit test + application-layer assertion |
| `CampaignResult` JSON output omits `evasion_rate` and `defence_profile` when `None` | Integration test asserting byte-identity |

## Migration

None. All changes are additive:
- New fields default to empty / None.
- Existing YAML files load unchanged until Phase 3 annotates them.
- Existing JSON campaign results round-trip through the extended model without modification.
- No database migrations (no database involved).
