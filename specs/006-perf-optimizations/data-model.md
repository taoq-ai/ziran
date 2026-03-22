# Data Model: Performance Optimizations

No new entities are introduced. This feature modifies the initialization and caching behavior of existing entities.

## Modified Entities

### AttackLibrary (existing)

**Module**: `ziran/application/attacks/library.py`

No structural changes. A module-level singleton cache is added alongside the class:

- `_INSTANCE: AttackLibrary | None` — cached default-config instance
- `get_attack_library(**kwargs) -> AttackLibrary` — factory function

The class itself remains unchanged. All vectors, indices, and methods are unaffected.

### ToolChainAnalyzer (existing)

**Module**: `ziran/application/knowledge_graph/chain_analyzer.py`

No structural changes. Internal optimization of `_find_indirect_chains()`:

- Pre-computed keyword index for pattern matching (local to method)
- Reachability check before path enumeration (new guard clause)

The `DangerousChain` entity, `ChainPatternInfo` type, and `DANGEROUS_PATTERNS` dict are unchanged.
