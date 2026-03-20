# Implementation Plan: Pre-compile Regex Patterns in Static Analysis

**Branch**: `perf/003-precompile-regex-patterns` | **Date**: 2026-03-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/003-precompile-regex-patterns/spec.md`

## Summary

Pre-compile regex patterns in the static analysis module so that patterns are compiled once at configuration load time rather than on every file analysis call. This eliminates ~3,000 redundant `re.compile()` calls when scanning a 100-file codebase. Pure performance optimization with zero behavior change.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic (config models), re (stdlib regex)
**Storage**: N/A
**Testing**: pytest
**Target Platform**: Linux/macOS (CI + developer machines)
**Project Type**: Library (security scanning toolkit)
**Performance Goals**: Each regex pattern compiled exactly once per config load (down from once per file per check)
**Constraints**: Zero behavior change; all existing tests must pass unmodified
**Scale/Scope**: 10 checks, ~30 patterns, codebases of 100+ files

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | PASS | Change is within application layer only (static_analysis) |
| Type Safety | PASS | Will add `re.Pattern` type annotations for compiled patterns |
| Test Coverage | PASS | Existing tests cover behavior; will add compilation verification tests |
| Async-First | N/A | Static analysis is synchronous (CPU-bound, no I/O) |
| Extensibility | PASS | Pre-compilation is transparent to config consumers |
| Simplicity | PASS | Minimal change — add compiled pattern fields to existing Pydantic models |
| Quality Gates | PASS | Will run ruff, mypy, pytest before merge |

## Project Structure

### Documentation (this feature)

```text
specs/003-precompile-regex-patterns/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
ziran/application/static_analysis/
├── config.py            # MODIFY: Add compiled_patterns fields to models
├── analyzer.py          # MODIFY: Use pre-compiled patterns instead of re.compile() per call

tests/unit/application/
└── test_static_analysis.py  # EXISTING: Must pass unmodified
```

**Structure Decision**: No new files needed. Changes are confined to two existing files in the static_analysis package. The config models gain compiled pattern fields; the analyzer functions consume them instead of calling `re.compile()` inline.
