# Contract: ATLAS Taxonomy

**Applies to**: Python import surface of `ziran.domain.entities.attack`.

## Public exports (new)

```python
from ziran.domain.entities.attack import (
    AtlasTactic,
    AtlasTechnique,
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_TO_TACTIC,
    AGENT_SPECIFIC_TECHNIQUES,
)
```

All five are module-level names in `ziran/domain/entities/attack.py` alongside the existing `OwaspLlmCategory` / `OWASP_LLM_DESCRIPTIONS` pair.

## `AtlasTactic`

```python
class AtlasTactic(StrEnum):
    RECONNAISSANCE = "AML.TA0002"
    RESOURCE_DEVELOPMENT = "AML.TA0003"
    # ... 15 entries matching the October 2025 ATLAS snapshot ...
```

- Value format: `AML.TA\d{4}`.
- Enum count: 15.
- Stable: values MUST NOT be renamed between releases (this is a public contract).

## `AtlasTechnique`

```python
class AtlasTechnique(StrEnum):
    LLM_PROMPT_INJECTION = "AML.T0051"
    # ... ≥ 60 entries ...
```

- Value format: `AML.T\d{4}(\.\d{3})?` (optional `.NNN` sub-technique).
- Enum count: ≥ 60 after Phase 3; grows additively.
- Stable: once added, values MUST NOT be renamed. Deprecations are handled by keeping the old enum value and marking it as deprecated in the description.

## `ATLAS_TECHNIQUE_DESCRIPTIONS`

```python
ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str] = {
    AtlasTechnique.LLM_PROMPT_INJECTION: "LLM Prompt Injection",
    # ...
}
```

- Keys: exactly the members of `AtlasTechnique` (enforced by unit test).
- Values: short human-readable name as published by MITRE at the snapshot date.

## `ATLAS_TECHNIQUE_TO_TACTIC`

```python
ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, AtlasTactic] = {
    AtlasTechnique.LLM_PROMPT_INJECTION: AtlasTactic.INITIAL_ACCESS,
    # ...
}
```

- Keys: exactly the members of `AtlasTechnique` (enforced by unit test).
- Values: canonical parent tactic per ATLAS.

## `AGENT_SPECIFIC_TECHNIQUES`

```python
AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique] = frozenset({
    # the 14 October-2025 AI-agent-specific techniques
})
```

- Cardinality: exactly 14 (enforced by unit test).
- `AGENT_SPECIFIC_TECHNIQUES` ⊂ `set(AtlasTechnique)` (enforced by unit test).

## Contract tests

Tests in `tests/unit/test_atlas_enum.py`:

1. `set(ATLAS_TECHNIQUE_DESCRIPTIONS) == set(AtlasTechnique)`
2. `set(ATLAS_TECHNIQUE_TO_TACTIC) == set(AtlasTechnique)`
3. `len(AGENT_SPECIFIC_TECHNIQUES) == 14`
4. `AGENT_SPECIFIC_TECHNIQUES.issubset(set(AtlasTechnique))`
5. Every `AtlasTactic` referenced in `ATLAS_TECHNIQUE_TO_TACTIC.values()` is a valid `AtlasTactic` member.
6. Every `AtlasTechnique` value matches the expected `AML.T\d{4}(\.\d{3})?` format.
7. Every `AtlasTactic` value matches `AML.TA\d{4}`.
