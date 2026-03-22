# Research: Performance Optimizations

## R1: CSafeLoader Availability and Fallback

**Decision**: Use `yaml.load(f, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))` as a drop-in replacement for `yaml.safe_load()`.

**Rationale**: PyYAML ships with C extensions by default when libyaml is available. `CSafeLoader` is functionally identical to `SafeLoader` but implemented in C. The `getattr` pattern provides transparent fallback. Benchmarks show 10x speedup (0.41s → 0.04s for 24 files locally).

**Alternatives considered**:
- `ruamel.yaml` with CLoader: adds a dependency, no significant advantage over CSafeLoader
- Pre-compiled msgpack/pickle cache: more complex, addressed separately in R2

## R2: Library Caching Strategy

**Decision**: Module-level singleton via `get_attack_library()` factory function. No kwargs = cached instance; any kwargs = fresh instance.

**Rationale**: Simplest approach that eliminates redundant parsing. The existing `tests/conftest.py` already uses a session-scoped fixture for the same purpose, validating that shared instances are safe for read-only consumers. The factory function extends this pattern to production code.

**Alternatives considered**:
- Pickle/msgpack on-disk cache with mtime invalidation: more complex, adds filesystem coupling, risk of stale cache bugs. Save for future if module-level singleton proves insufficient.
- `functools.lru_cache`: doesn't work well with keyword arguments and mutable defaults.
- Class-level `__new__` singleton: breaks the explicit fresh-instance path needed by benchmarks.

## R3: Benchmark Iteration Count

**Decision**: Reduce `_measure_operation()` default from `iterations=3` to `iterations=1`.

**Rationale**: The warm-up run already eliminates cold-start bias. Performance thresholds are generous (30s) for CI runners. A single measured iteration is sufficient for regression detection. Combined with CSafeLoader + singleton, total benchmark time drops from minutes to seconds.

**Alternatives considered**:
- Keep 3 iterations but use cached library: still 3x the work for marginal statistical benefit.
- `@pytest.mark.slow` separation: doesn't fix the root cause, just hides it.

## R4: Chain Analyzer Pre-Filtering Strategy

**Decision**: Two-phase optimization:
1. **Keyword pre-index**: Before the nested loop, extract keywords from each tool ID and build a reverse index mapping pattern keywords to tool IDs. Only iterate over (source, target) pairs where both tools have at least one keyword overlapping with a pattern's source/target keywords respectively.
2. **Reachability check**: Before calling `nx.all_simple_paths()`, check `nx.has_path(graph, source, target)` which is O(V+E) BFS — much cheaper than enumerating all paths.

**Rationale**: The `_match_pattern` method uses substring and keyword overlap matching. By pre-computing which tools could possibly match which pattern roles, we skip the majority of T^2 pairs. The reachability check avoids the expensive `all_simple_paths` call for disconnected pairs.

**Alternatives considered**:
- Batch `all_simple_paths` with target sets: NetworkX doesn't natively support multi-target path enumeration efficiently.
- Precomputed transitive closure: O(V^3) space and time, worse for sparse graphs.
- Parallel processing: adds complexity, the algorithmic fix is more effective.
