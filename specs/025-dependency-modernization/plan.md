# Implementation Plan: Dependency Modernization — Retire Security Dismissals

**Branch**: `025-dependency-modernization` | **Date**: 2026-06-22 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/025-dependency-modernization/spec.md`

## Summary

Forward-modernize the agent-framework stack (#332 Option C) so the spec-024 not-reachable dismissals for **litellm** and the **langchain family** become real fixes. Empirically (see research.md) the coherent resolution is: **crewai 1.14.7, rich 14.3.4, litellm 1.89.3, openai 2.43, langchain-core 1.4.8, langgraph 1.2.2, langchain-openai 1.3.2, langgraph-checkpoint 4.1.1** — converging only when the `crewai`, `langchain`-family, `litellm`, and core `rich` caps are all relaxed together. The cost is **code migration across four surfaces**: the CrewAI adapter (0.203→1.14 API), the LangChain adapter (1.0 import moves), the langgraph pentest orchestrator (0.6→1.2), and the `rich` 13→14 CLI call sites — plus the openai 1→2 ripple in the litellm client path.

This is an application-code change (unlike spec 024), so the type-safety and test-coverage gates fully apply.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11/3.12/3.13); TypeScript frontend unaffected.
**Primary Dependencies (upgraded)**: crewai 0.x→1.14, rich 13→14, litellm →1.89, openai 1→2, langchain/-core/-openai 0.x→1.x, langgraph 0.6→1.2. Tooling unchanged (uv, pip-audit, npm audit).
**Storage**: N/A. Touched persisted artifact: `docs/security/risk-acceptances.md` (rows removed).
**Testing**: existing pytest matrix (unit+integration), `mypy ziran/` (strict), ruff/format, `npm run build`, the spec-024 `dependency-audit` gate — all as the regression oracle.
**Target Platform**: Linux CI + local CLI.
**Project Type**: web (Python `ziran/` + React `ui/`); only the Python side changes.
**Performance Goals**: N/A (no runtime perf target; CLI rendering must remain correct).
**Constraints**: single coherent lock resolution (FR-001/FR-002); zero new Dependabot alerts of any severity (FR-009, clarification Q3); open critical/high stays zero (FR-010).
**Scale/Scope**: ~5 coordinated major bumps; 4 code-migration surfaces (~5 source files) + 7 rich-importing files to verify; ~12 alerts move dismissed→fixed.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | ✅ | Changes confined to infrastructure adapters (`crewai_adapter`, `langchain_adapter`) + the application pentest orchestrator + CLI rendering; no layer-boundary inversion. Domain untouched. |
| II. Type Safety (mypy strict) | ⚠️ Applies | Adapter refactors are typed code — `mypy ziran/` must stay clean across the new majors (new return types e.g. crewai `CrewOutput`, langchain import moves). Real work, not N/A. |
| III. Test Coverage ≥85% (CI 80%) | ✅ | No new logic paths; existing adapter/orchestrator tests are the correctness oracle (FR-005). Coverage must not drop below the CI 80% floor. |
| IV. Async-First | ✅ | Preserved — the CrewAI adapter keeps `asyncio.to_thread(kickoff)`; litellm client stays async. |
| V. Extensibility via Adapters | ✅ | Reinforces it — adapters refactored in place behind existing interfaces. |
| VI. Simplicity | ✅ | Migrate APIs forward; do not add compatibility shims or pin-arounds (spec edge case). |
| Quality Gates | ✅ Gate | ruff/format/mypy/pytest(≥80%)/npm build + dependency-audit run unchanged; they are the FR-004 acceptance evidence. |

**Result: PASS** — no violations. Principle II is the area demanding care (typed adapter refactors), not a deviation.

## Project Structure

### Documentation (this feature)

```text
specs/025-dependency-modernization/
├── plan.md, research.md, data-model.md, quickstart.md
├── contracts/
│   ├── target-resolution.md     # the pinned Option-C version set + which alerts fix vs stay
│   └── adapter-migration.md      # the API contracts the refactored adapters must satisfy
└── tasks.md                      # (/speckit.tasks)
```

### Source Code — files this feature touches

```text
pyproject.toml                                   # relax caps: crewai<2, rich<15, litellm>=1.84, langchain* 1.x
uv.lock                                          # regenerated to the Option-C set
ziran/infrastructure/adapters/crewai_adapter.py  # kickoff()->CrewOutput, Crew/agents/tasks API (0.203->1.14)
ziran/infrastructure/adapters/langchain_adapter.py # AgentExecutor + langchain_community import moves (1.0)
ziran/application/pentesting/agent.py            # langgraph StateGraph API (0.6->1.2)
ziran/infrastructure/llm/litellm_client.py       # openai 1->2 ripple (mostly internal to litellm)
ziran/**/*.py (7 rich importers)                 # rich 13->14 render call sites (Console/Table/Live/Panel/Prompt/Spinner)
docs/security/risk-acceptances.md                # remove now-fixed rows
.github/workflows/ci.yml                          # shrink the pip-audit --ignore-vuln list to the no-fix items
```

**Structure Decision**: Application-code migration confined to two infrastructure adapters, one application orchestrator, the LLM client, and CLI rendering call sites — plus the manifest/lock and the spec-024 security records. No new modules; existing adapter interfaces are preserved.

## Implementation Phases (slice → story)

| Phase | Story | Scope |
|-------|-------|-------|
| **Foundational** | — | Relax the declared caps and regenerate the lock to the Option-C set (research R1). Blocking: nothing compiles/tests until the lock lands. |
| **Refactor** | US2 (P2) | The four migration surfaces: CrewAI adapter→1.14, LangChain adapter→1.0 imports, langgraph orchestrator→1.2, rich 13→14 call sites, openai 1→2 ripple. The bulk of the code work, and the prerequisite for US1's gates to pass. |
| **Security outcome** | US1 (P1) | Confirm the gates are green and the litellm + langchain-family alerts are fixed-by-upgrade; raise any straggler floor to its patched line where the resolver allows. |
| **Reconcile** | US3 (P3) | Remove the now-fixed rows from `risk-acceptances.md` + the pip-audit ignore list; verify the audit gate stays green and only no-fix items remain. |

> **Priority note**: although US1 is P1 (the *outcome*), it depends on US2's refactor (the *enabler*) to go green — the lock cannot pass gates until the adapters are migrated. Execution order is Foundational → Refactor (US2) → verify outcome (US1) → reconcile (US3).

## Known residual (from research)

- **langchain caps at 1.3.2** in this resolution; flooring `>=1.3.9` is unsatisfiable. So the `langchain` GHSA-gr75 alert (#108, path-traversal in **unused** file-search loaders) **stays a not-reachable dismissal** — not one of the ~12 that convert to fixed. The plan keeps that one row in `risk-acceptances.md`.
- **chromadb (no fix, 1.0–1.5.9 all affected)** and **diskcache** remain not-reachable dismissals (out of scope, spec 024).

## Complexity Tracking

> No constitution violations — section intentionally empty.
