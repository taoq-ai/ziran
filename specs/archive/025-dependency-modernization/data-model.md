# Data Model: Dependency Modernization

**Date**: 2026-06-22 | **Feature**: 025-dependency-modernization

No runtime/domain data models change. The "entities" are the dependency-resolution and security artifacts the work manipulates.

## Entity: Declared constraint set (`pyproject.toml`)

The per-dependency version floors/caps. The lever of this feature: raising the crewai/rich/litellm/langchain-family floors (see contracts/target-resolution.md). Validation: the regenerated lock must resolve (EXIT 0) and keep open critical/high at zero.

## Entity: Resolved dependency set (`uv.lock`)

The single committed source of truth pinning every transitive version. Must converge on the Option-C versions (research R1) and install deterministically (`--frozen`).

## Entity: Framework integration (code)

The adapters/orchestrator that must work on the new majors — CrewAI adapter, LangChain adapter, langgraph pentest orchestrator, LLM client, CLI rendering. Contract: `contracts/adapter-migration.md`. State: *pre-migration* (compiles on old majors) → *migrated* (compiles + tests green on new majors). Interfaces unchanged.

## Entity: Alert disposition record

Per affected advisory: `{alert#, package, ghsa, prior_state: dismissed, new_state}` where `new_state ∈ {fixed, kept-dismissed}`. Drives both the `risk-acceptances.md` row removals and the `pip-audit --ignore-vuln` shrink. Full table in `contracts/target-resolution.md`.

**Rules**:
- `fixed` ⇒ the row is removed from the decision record AND its GHSA removed from the ignore list AND the dependency is no longer at a vulnerable version.
- `kept-dismissed` ⇒ row + ignore entry remain (langchain #108 if unfixed, chromadb #84, diskcache #41).
- No new advisory may appear (FR-009); if one does, it is upgraded away (becomes neither row nor ignore entry).

## Relationships

```text
Declared constraint set ──regenerates──▶ Resolved dependency set
        │                                          │
        │ forces new majors                        │ pins vulnerable→patched
        ▼                                          ▼
Framework integration (migrate) ──makes green──▶ Quality gates
Alert disposition record ──shrinks──▶ risk-acceptances.md + pip-audit ignore list
```
