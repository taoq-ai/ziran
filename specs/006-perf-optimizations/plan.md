# Implementation Plan: Performance Optimizations

**Branch**: `006-perf-optimizations` | **Date**: 2026-03-22 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/006-perf-optimizations/spec.md`

## Summary

Four performance issues (#211, #214, #215, #216) are addressed to reduce YAML parsing time by 10x, eliminate redundant library instantiation across benchmarks, reduce CI benchmark runtime from minutes to seconds, and optimize chain analysis from O(T^2) to near-linear for typical inputs.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: PyYAML (CSafeLoader), NetworkX (graph algorithms), Pydantic (validation)
**Storage**: N/A (in-memory only)
**Testing**: pytest with markers (`@pytest.mark.unit`, `@pytest.mark.integration`)
**Target Platform**: Linux/macOS (CI + local dev)
**Project Type**: Library/CLI
**Performance Goals**: Library init < 0.1s locally; chain analysis < 10s for 50+ tools; benchmark suite < 60s
**Constraints**: No behavioral changes; backward-compatible API
**Scale/Scope**: 24 YAML files (~732KB), 7+ benchmark modules, 1 chain analyzer

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | PASS | Changes stay within application layer; no dependency direction violations |
| Type Safety | PASS | `get_attack_library()` will have full type annotations; return type is `AttackLibrary` |
| Test Coverage | PASS | Existing tests cover all modified paths; no new untested code paths |
| Async-First | N/A | YAML parsing and graph analysis are CPU-bound, not I/O-bound |
| Extensibility via Adapters | PASS | No adapter changes; singleton is bypassed for custom configs |
| Simplicity | PASS | Module-level singleton is the simplest caching approach; no new abstractions |
| Quality Gates | PASS | ruff, mypy, pytest will be run post-implementation |

## Project Structure

### Documentation (this feature)

```text
specs/006-perf-optimizations/
├── spec.md
├── plan.md              # This file
├── research.md
├── data-model.md
├── quickstart.md
└── checklists/
    └── requirements.md
```

### Source Code (files to modify)

```text
ziran/application/attacks/library.py          # CSafeLoader + singleton factory
ziran/application/knowledge_graph/chain_analyzer.py  # O(T²) optimization
ziran/application/agent_scanner/scanner.py    # Use get_attack_library()
benchmarks/performance_metrics.py             # Reduce iterations + use singleton
benchmarks/inventory.py                       # Use get_attack_library()
benchmarks/owasp_coverage.py                  # Use get_attack_library()
benchmarks/benchmark_comparison.py            # Use get_attack_library()
benchmarks/comparative_analysis.py            # Use get_attack_library()
benchmarks/utility_metrics.py                 # Use get_attack_library()
```

**Structure Decision**: No new files or directories. All changes are modifications to existing modules.

## Implementation Phases

### Phase 1: CSafeLoader (Issue #211)

**File**: `ziran/application/attacks/library.py:325`

Replace `yaml.safe_load(f)` with `yaml.load(f, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))`.

Single-line change with automatic fallback. Expected 10x speedup on YAML parsing.

### Phase 2: Singleton Factory (Issue #216)

**File**: `ziran/application/attacks/library.py`

Add at module level (after class definition):

```python
_INSTANCE: AttackLibrary | None = None

def get_attack_library(**kwargs: Any) -> AttackLibrary:
    """Return a cached AttackLibrary singleton for default configuration."""
    global _INSTANCE
    if kwargs:
        return AttackLibrary(**kwargs)
    if _INSTANCE is None:
        _INSTANCE = AttackLibrary()
    return _INSTANCE
```

Export `get_attack_library` from the module's `__all__` if one exists.

### Phase 3: Update Callers (Issues #214, #216)

Update all default-config callers to use `get_attack_library()`:

| File | Line | Change |
|------|------|--------|
| `benchmarks/inventory.py` | 29 | `AttackLibrary()` → `get_attack_library()` |
| `benchmarks/owasp_coverage.py` | 35 | `AttackLibrary()` → `get_attack_library()` |
| `benchmarks/benchmark_comparison.py` | 506 | `AttackLibrary()` → `get_attack_library()` |
| `benchmarks/comparative_analysis.py` | 205 | `AttackLibrary()` → `get_attack_library()` |
| `benchmarks/utility_metrics.py` | 45 | `AttackLibrary()` → `get_attack_library()` |
| `benchmarks/performance_metrics.py` | 94 | `_bench_library_filter_category`: use singleton |
| `benchmarks/performance_metrics.py` | 103 | `_bench_library_filter_owasp`: use singleton |
| `benchmarks/performance_metrics.py` | 159 | throughput calculation: use singleton |
| `ziran/application/agent_scanner/scanner.py` | 149 | fallback: `get_attack_library(custom_dirs=...)` or `get_attack_library()` |

**Keep `AttackLibrary()` direct instantiation** in `_bench_library_init()` (line 86) — it measures fresh init time.

Reduce `_measure_operation()` default `iterations` from 3 to 1 (line 29).

### Phase 4: Chain Analyzer Optimization (Issue #215)

**File**: `ziran/application/knowledge_graph/chain_analyzer.py`

Optimize `_find_indirect_chains()` (lines 198-257):

1. **Pre-compute keyword index**: Before the nested loop, extract keywords from all tool IDs using `_to_keywords()`. Build a reverse mapping: `pattern_keyword → set[tool_id]`. For each pattern `(source_pattern, target_pattern)`, compute candidate source and target tool sets by keyword overlap. Only iterate over pairs in the intersection.

2. **Reachability guard**: Before `nx.all_simple_paths()`, add `if not nx.has_path(self.graph.graph, source_id, target_id): continue`. This is O(V+E) BFS vs the potentially expensive path enumeration.

Both optimizations are internal to the method — no signature or return type changes.

## Verification

1. `cd src && ruff check .` — zero lint errors
2. `cd src && ruff format --check .` — zero drift
3. `cd src && python -m mypy ziran/ benchmarks/` — zero type errors
4. `cd src && pytest tests/ -x -m "not integration"` — all unit tests pass
5. `cd src && pytest tests/ -k "chain" -x` — chain analyzer tests pass with identical results
6. `cd src && python -c "import yaml; print(hasattr(yaml, 'CSafeLoader'))"` — verify C extension availability

## Complexity Tracking

No constitution violations. No complexity justifications needed.
