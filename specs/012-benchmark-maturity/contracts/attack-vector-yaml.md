# Contract: Attack Vector YAML Schema

**Applies to**: Every file under `ziran/application/attacks/vectors/*.yaml`.

## Change summary

One additive field: `atlas_mapping`. All existing fields retain their current shape, defaults, and semantics.

## Schema (additions only)

```yaml
- id: example_vector_id
  name: Example Vector
  category: indirect_injection
  target_phase: execution
  description: …
  severity: high
  prompts: […]
  tags: [rag-poisoning]

  # Existing mapping — unchanged:
  owasp_mapping: [LLM01]

  # NEW — list of MITRE ATLAS technique IDs (strings matching AtlasTechnique enum values).
  # Empty list is accepted until Phase 3 completes; after Phase 3 the CI lint flags
  # any empty list.
  atlas_mapping:
    - AML.T0051   # LLM Prompt Injection
    - AML.T0070   # Retrieval Content Crafting
```

## Rules

| Rule | Enforcement |
|---|---|
| `atlas_mapping` values must match `AtlasTechnique` enum | Pydantic validation when library loads YAML |
| Unknown technique IDs fail fast with a clear error | Pydantic `ValueError` surfacing the bad value |
| Duplicate technique IDs within the same vector are deduplicated silently (but a warning is logged) | Library loader post-processing |
| The field is optional at the YAML layer (defaults to `[]`) | Pydantic `default_factory=list` |
| CI gate after Phase 3: no vector may have empty `atlas_mapping` on `main` | `benchmarks/atlas_coverage.py` non-zero exit |

## Backwards compatibility

- YAML files without `atlas_mapping` load as they do today (empty list). No migration needed for downstream consumers of the YAML format.
- All existing vectors retain their existing `owasp_mapping`; neither taxonomy affects the other.
