# Research: Dependency Modernization (#332 Option C)

**Date**: 2026-06-22 | **Feature**: 025-dependency-modernization

## R1 — The coherent resolution (empirically verified)

**Decision**: Relax the declared caps together — `crewai` `<1`→`<2`, core `rich` `<14`→`<15`, `litellm` floor `>=1.84`, and the langchain family (`langchain`, `langchain-community>=0.4`, `langchain-openai`, `langchain-core`, `langgraph`) to `1.x` — and regenerate the lock.

**Result** (`uv lock`, EXIT 0): the tree converges on:

| Package | Was | Resolves to | Security target | Status |
|---|---|---|---|---|
| crewai | 0.203.2 | **1.14.7** | (latest) | ✓ |
| rich | 13.x | **14.3.4** | (core bump) | ✓ render-verify |
| litellm | 1.74.9 | **1.89.3** | ≥1.84 | ✓ FIXED (2 crit + 3 high) |
| openai | 1.x | **2.43.0** | (2.x) | ✓ |
| langchain-core | 0.3.86 | **1.4.8** | ≥1.2.22 | ✓ FIXED (3) |
| langgraph | 0.6.11 | **1.2.2** | ≥1.0.10 | ✓ FIXED |
| langgraph-checkpoint | 3.0.1 | **4.1.1** | ≥4.0.0 | ✓ FIXED |
| langchain-openai | 0.3.x | **1.3.2** | ≥1.1.14 | ✓ FIXED |
| langchain-text-splitters | 0.3.11 | **1.1.2** | ≥1.1.2 | ✓ FIXED |
| langchain | 0.3.30 | **1.3.2** | ≥1.3.9 | ✗ capped below fix (see R2) |
| chromadb | (old) | 1.1.1 | none exists | stays dismissed |

**Rationale**: This is the only path that reaches patched litellm/langchain — `litellm 1.84+` requires `openai 2.x`, which is only compatible with `crewai 1.14.x`, which pulls `rich ≥14.2` (via `crewai-cli → textual`), colliding with the old `rich<14`. Relaxing all four caps lets uv converge.

**Alternatives**: Option B (pin crewai *down* to 0.95, no rich bump) — rejected by the user in clarification (wants crewai at latest + a real adapter refactor). Keeping dismissals — rejected (the point is to fix them).

## R2 — langchain meta-package capped at 1.3.2

**Decision**: Accept that `langchain` resolves to **1.3.2**; flooring `langchain>=1.3.9` is **unsatisfiable** in the Option-C tree (something in the modern set pins it ≤1.3.2).

**Consequence**: the `langchain` GHSA-gr75 advisory (alert #108, fixed 1.3.9 — path traversal in **file-search loaders ZIRAN does not use**) **stays a not-reachable dismissal**. It is *not* among the ~12 that convert to fixed. `langchain-core` (the package carrying the more serious deserialization advisories) *does* reach 1.4.8 and is fixed.

**Rationale**: forcing 1.3.9 breaks resolution; the residual advisory is in an unused code path, so the existing not-reachable justification still holds. Documented as a kept row in `risk-acceptances.md`.

## R3 — CrewAI adapter migration (0.203 → 1.14)

**Decision**: Refactor `ziran/infrastructure/adapters/crewai_adapter.py` to the crewai 1.x API. The core surface (`from crewai import Crew`, `crew.kickoff(inputs=...)`, `crew.agents`, `crew.tasks`) is stable, but **`kickoff()` returns a `CrewOutput` object in 1.x** (not a string) — the adapter must extract the text (`.raw` / `str(result)`) when building its `AgentResponse`.

**Rationale**: this is the spec's explicit refactor goal (US2). Keep the existing `asyncio.to_thread(kickoff)` async bridge (Principle IV).

**Verify against**: `tests/integration/test_crewai_adapter.py`, `tests/unit/test_langchain_crewai_adapters.py`.

## R4 — LangChain adapter migration (→ 1.0)

**Decision**: Update `ziran/infrastructure/adapters/langchain_adapter.py` import paths for langchain 1.0:
- `from langchain.agents import AgentExecutor` — verify it still resolves in langchain 1.x or move to its new home (`langchain` may re-export, or it relocates to `langchain-classic`).
- `from langchain_community.callbacks.manager import ...` — langchain-community 0.4.x may relocate callbacks; update or replace with the `langchain-core` callbacks equivalent.

**Rationale**: langchain 1.0 split packages (`langchain-classic`, `langchain-core` 1.x). Migrate imports rather than pin back (Principle VI / spec edge case).

**Verify against**: the langchain adapter tests + a representative scan.

## R5 — langgraph orchestrator (0.6 → 1.2)

**Decision**: Verify `ziran/application/pentesting/agent.py`'s `StateGraph` usage (`add_node`, `add_edge`, `compile()`, `END`) against langgraph 1.x. The graph-building API is largely stable across 1.0; the compile-without-checkpointer pattern is unchanged.

**Rationale**: low-risk but must be confirmed; the pentest eval gate exercises this path.

## R6 — rich 13 → 14 CLI call sites

**Decision**: Verify the 7 `rich`-importing modules render correctly on rich 14 — surfaces in use: `Console`, `Table`, `Live`, `Panel`, `Prompt`, `Spinner`, `RichHandler`. rich 14's breaking changes are minor (mostly internal/measurement); spot-check table/report/progress rendering.

**Rationale**: rich is the pervasive CLI output dependency; FR-003/SC-003 require verified-correct rendering after the major bump. This is verification-heavy, low code-change.

## R7 — openai 1 → 2 ripple

**Decision**: The openai 2.x bump is consumed mainly *inside* litellm (the client path `litellm.acompletion`/`aembedding`); ZIRAN does not call the openai SDK directly in the hot path. Verify the litellm client smoke (`litellm_client.py`) and the adaptive-LLM strategy still work; no direct openai-SDK call sites to migrate were found.

## R8 — Zero-new-alerts bar (clarification Q3)

**Decision**: After re-locking, the modernized set MUST introduce no new Dependabot alert of any severity. The CI `dependency-audit` gate (pip-audit `--all-extras` + npm audit) is the enforcement point; any new advisory on crewai 1.14 / rich 14 / openai 2 / langchain 1.x must be upgraded away before completion (not recorded). crewai 1.14 being *current* (vs the old 0.95 alternative) makes this achievable.

## R9 — Alert state transition (deferred mechanism, clarification Q2)

**Decision (mechanism chosen here for the plan)**: the ~12 fixed advisories' dismissed alerts will be **reopened via the API** so that, once the patched lock is on the default branch and Dependabot rescans, they close as *fixed*; the kept not-reachable rows (langchain #108, chromadb, diskcache) stay dismissed. Final confirmation happens at implementation.

## Resolved unknowns

All Technical Context items resolved; no `NEEDS CLARIFICATION` remain. Target versions and the migration surfaces are empirically grounded (uv lock + code grep).
