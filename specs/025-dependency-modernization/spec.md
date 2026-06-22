# Feature Specification: Dependency Modernization — Retire Security Dismissals

**Feature Branch**: `025-dependency-modernization`  
**Created**: 2026-06-22  
**Status**: Draft  
**Input**: User description: "Upgrade litellm and the langchain family to fixed versions so the not-reachable dismissals from spec 024 become real upgrades." Refined in clarification to the forward-modernization path (#332 Option C): upgrade the CrewAI integration to the latest version and refactor its adapter, accepting the core command-line rendering major bump.

## User Scenarios & Testing *(mandatory)*

Spec 024 cleared the security backlog, but **12 alerts (including 2 criticals)** could only be *dismissed as not-reachable* — they couldn't be fixed because the `crewai` integration transitively pinned `litellm` and the `langchain` family at vulnerable versions. The #332 investigation showed why: the modern, patched versions of those packages are only reachable by **moving the whole framework stack forward** — upgrading the `crewai` integration to its latest release and accepting the dependency changes that come with it (a major bump of the core command-line rendering library, the newer vendor LLM-client major, and the `langchain` major migration). A maintainer wants those dismissed alerts converted into genuine upgrades by modernizing the stack — **upgrading the CrewAI integration to the latest version and refactoring its adapter accordingly** — with every affected framework integration still working and the security records reconciled to reflect "fixed" rather than "accepted risk".

### User Story 1 - Convert the litellm + langchain alerts from dismissed to fixed (Priority: P1) 🎯 MVP

A maintainer wants the dismissed litellm and langchain-family vulnerabilities **actually patched** by upgrading to fixed versions, so the project no longer carries standing risk-acceptances for them and the alerts close as *fixed*.

**Why this priority**: This is the entire point of the work and delivers the security value — it retires the 2 critical + several high/medium standing dismissals by upgrading to patched releases. It is the MVP: even before the bookkeeping is perfect, having the patched versions in the lock is the substantive win.

**Independent Test**: Raise the declared version floors for the affected dependencies, re-resolve the locked dependency set, run the full quality-gate suite, and confirm the litellm and langchain-family alerts are resolved by upgrade (no longer present at vulnerable versions) with no test or build regressions.

**Acceptance Scenarios**:

1. **Given** the project's declared dependency constraints, **When** the litellm and langchain-family floors are raised to their patched lines and the lock is regenerated, **Then** the resolved versions are the patched ones and the full gate suite (lint, format, type-check, tests at the enforced coverage floor, frontend build) passes.
2. **Given** the regenerated lock, **When** the security alerts are reviewed, **Then** the litellm and langchain-family alerts are in a *fixed* state (resolved by upgrade), not dismissed.
3. **Given** the upgrade bumps the core command-line rendering library to a new major, **When** the CLI is run, **Then** its rendered output (tables, reports, progress) still displays correctly.

---

### User Story 2 - Refactor the framework integrations onto the new majors (Priority: P2)

A maintainer wants the agent-framework integrations affected by the upgrades — the **CrewAI adapter (refactored to the latest CrewAI API)**, the LangChain adapter, the graph-based pentest orchestrator, and the multi-vendor LLM client — to work correctly on the new major versions, so no scanning capability regresses and the modernization is real rather than pinned-around.

**Why this priority**: The upgrades cross major-version boundaries — the CrewAI integration moves to its latest major (the adapter refactor is the explicit goal), plus a LangChain major migration and a newer LLM-client major. Each can change behavior, so verified, refactored compatibility is what makes the P1 upgrade safe to ship. It is P2 because it is the correctness guard rail around P1.

**Independent Test**: After the upgrades, run the tests covering the CrewAI adapter, the LangChain adapter, the pentest orchestrator, and the LLM client, and confirm each passes on the new majors (and a representative scan still completes end-to-end).

**Acceptance Scenarios**:

1. **Given** the CrewAI integration upgraded to its latest major, **When** the CrewAI adapter is refactored to the new API and exercised, **Then** it wraps and invokes a crew correctly (the create/invoke path works on the new version).
2. **Given** the upgraded dependencies, **When** the LangChain adapter and the graph-based pentest orchestrator are exercised, **Then** they operate correctly under the new major versions (imports resolve, agents are wrapped and invoked, the orchestrator graph builds and runs).
3. **Given** the LLM client path now runs on the newer vendor-client major, **When** a completion/embedding call is made through it, **Then** it behaves as before.

---

### User Story 3 - Reconcile the security records (Priority: P3)

A maintainer wants the in-repo decision record and the CI audit-gate suppression list updated to drop the entries that are now genuinely fixed, so the records reflect reality and the suppression list shrinks to only the truly un-fixable items.

**Why this priority**: Bookkeeping that keeps the security posture honest and prevents the suppression list from masking future regressions. Lowest priority because it follows the substantive upgrade, but required so accepted-risk no longer covers fixed items.

**Independent Test**: Inspect the decision record and the CI suppression list and confirm the now-fixed advisories are removed from both, leaving only the items with no available fix; confirm the audit gate still passes.

**Acceptance Scenarios**:

1. **Given** the litellm and langchain-family advisories are now fixed by upgrade, **When** the decision record and the CI audit-gate suppression list are reviewed, **Then** those advisories no longer appear in either (they are fixed, not suppressed).
2. **Given** the reconciled suppression list, **When** the dependency-audit gate runs, **Then** it passes, and the only remaining accepted-risk items are those with no available fix.

---

### Edge Cases

- **Coupled resolution**: the litellm fix requires a newer vendor-client major, which is only compatible with the latest CrewAI major, which in turn pulls the core command-line rendering library to a new major — the upgrade must be applied as one coherent resolution, not piecemeal, or it will not converge.
- **A targeted advisory not fully patched by the resolved version**: if the resolver lands a version just below a specific advisory's patched release, the floor for that package MUST be raised to the patched version so the alert closes — unless raising it makes the whole resolution unsatisfiable, in which case that one advisory stays a recorded not-reachable dismissal rather than blocking the upgrade (this is the known case for the `langchain` meta-package, which caps below its file-search advisory's fix while `langchain-core` — carrying the serious advisories — does upgrade).
- **LangChain major migration breakage**: the major migration may relocate or rename APIs the adapter/orchestrator rely on; these MUST be migrated, not worked around by pinning back.
- **Zero new alerts from the new versions**: the upgraded framework majors MUST NOT introduce any new Dependabot alert of any severity; if the modernized set would surface a new advisory, it MUST be resolved before completion (not merely recorded).
- **No-fix items remain**: the two advisories with no available patched version in any release stay as recorded not-reachable dismissals and are explicitly out of scope here.
- **Core CLI rendering bump in scope**: the chosen resolution upgrades the CrewAI integration to its latest release, which forces a major bump of the core command-line rendering library; that bump is in scope, and the CLI's rendered output (tables, reports, progress) MUST be verified to still render correctly.

## Clarifications

### Session 2026-06-22

- Q: If the original plan's CrewAI *downgrade* proved unworkable, what's the fallback? → A: Don't downgrade — **upgrade the CrewAI integration to the latest version and treat the adapter refactoring as the goal.** This adopts the forward-modernization path (#332 Option C): the core command-line rendering major bump is now **in scope**, not deferred.
- Q: How should the previously-dismissed litellm/langchain alerts end up as "fixed" rather than "dismissed"? → A: Decide the exact mechanism during planning (operational detail).
- Q: Acceptance bar for the new framework versions' own security posture? → A: **Zero new alerts of any severity** — the modernization must not introduce any new Dependabot alert (any severity); if it would, that alert must be resolved before completion, not merely recorded.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The litellm dependency and the langchain-family dependencies MUST be upgraded to versions that resolve their outstanding advisories, by raising the project's declared version floors to the patched lines.
- **FR-002**: The upgrade MUST be reflected in the committed, regenerated lockfile as the single source of truth, with deterministic installs preserved.
- **FR-003**: The CrewAI integration MUST be upgraded to its latest release; the resulting major bump of the core command-line rendering dependency is in scope, and the CLI's rendered output MUST be verified to still display correctly.
- **FR-004**: After the upgrade, the full existing quality-gate suite (lint, format, type-check, tests at the enforced coverage floor, and the frontend build) MUST pass with no regressions.
- **FR-005**: The CrewAI adapter MUST be refactored to the latest CrewAI API, and the LangChain adapter, the graph-based pentest orchestrator, and the multi-vendor LLM client MUST function under the upgraded versions — all verified by their existing tests (and a representative end-to-end scan).
- **FR-006**: Each affected advisory MUST end in a *fixed* state (resolved by upgrade); where the resolved version would sit one patch below a specific advisory's fix, the floor for that package MUST be raised so the advisory closes — **unless raising it makes the resolution unsatisfiable**, in which case that single advisory remains a recorded not-reachable dismissal (documented, with justification).
- **FR-007**: The now-fixed advisories MUST be removed from the in-repo security decision record and from the CI dependency-audit suppression list, leaving only the items with no available fix.
- **FR-008**: The CI dependency-audit gate MUST remain green after the suppression list is shrunk.
- **FR-009**: The modernized dependency set MUST NOT introduce any new Dependabot alert of any severity; if it would, that advisory MUST be resolved (upgraded away) before completion, not merely recorded.
- **FR-010**: After completion, the count of open critical and high alerts MUST remain zero (no regression of the spec-024 outcome), with the litellm + langchain-family items now counted as fixed rather than dismissed.

### Key Entities

- **Declared version floor**: the project's stated minimum allowed version for a dependency; raising it is the lever that moves the resolution onto patched releases.
- **Resolved dependency set**: the regenerated lock that pins every dependency; the coherent set that must converge on patched versions of litellm and the langchain family (which entails the latest CrewAI and the core CLI rendering major bump).
- **Affected framework integration**: the LangChain adapter, graph-based pentest orchestrator, CrewAI adapter, and LLM client that must keep working across the major upgrades.
- **Security decision record + suppression list**: the in-repo record and CI ignore list whose entries shrink as advisories move from accepted-risk to fixed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The litellm advisories (including both criticals) and the langchain-family advisories move from *dismissed* to *fixed by upgrade* — except the residual `langchain` file-search advisory that caps below its fix, which remains a recorded not-reachable dismissal — verifiable on the Security tab.
- **SC-002**: The number of open Dependabot alerts of **any** severity does not increase (the modernization introduces no new alert), open critical/high stays at zero, and standing risk-acceptances reduce to only the no-fix items.
- **SC-003**: After the core command-line rendering library's major bump, the CLI's rendered output (tables, reports, progress) still displays correctly.
- **SC-004**: The full quality-gate suite and the frontend build pass with no regressions, and a representative end-to-end scan still completes.
- **SC-005**: The CI dependency-audit suppression list contains only the no-fix items after reconciliation, and the gate passes.
- **SC-006**: The LangChain, CrewAI, and pentest-orchestrator features pass their existing tests under the upgraded versions.

## Assumptions

- The forward-modernization path (#332 Option C) is the chosen approach: upgrade the CrewAI integration to its latest release, accept the consequent major bump of the core command-line rendering library, the newer vendor LLM-client major, and the langchain major migration — together these make the patched litellm and langchain-family versions reachable.
- The CrewAI adapter will be refactored to the latest CrewAI API as the explicit goal (not pinned around).
- The modernized stack introduces no new Dependabot alert of any severity; if one appears, it is resolved within this work.
- The two advisories with no available fix in any release (a critical and a medium, both not-reachable) remain recorded dismissals and are out of scope.
- The core command-line rendering library's new major is API-compatible enough for ZIRAN's CLI rendering, or the rendering call sites are updated as part of this work.
- The existing quality-gate suite is a sufficient regression oracle; the affected framework integrations have tests that meaningfully exercise them.
- The exact mechanism for moving the previously-dismissed alerts to a *fixed* state is decided during planning.
- Repository security state can be updated so resolved alerts close as fixed.

## Dependencies

- The committed dependency manifest and lockfile.
- The existing CI quality-gate matrix, the frontend build, and the dependency-audit gate (from spec 024) as the regression oracle.
- The in-repo security decision record and the CI suppression list introduced in spec 024.
- Issues #330 / #332 (this implements #332 Option C, the forward-modernization path); spec 024 (the dismissals this retires).
