# Feature Specification: Security Alert Remediation

**Feature Branch**: `024-security-alert-remediation`  
**Created**: 2026-06-18  
**Status**: Active  
**Input**: User description: "Security alert remediation: clear the open GitHub Security backlog — 88 Dependabot alerts and 5 CodeQL code-scanning alerts, enable secret scanning + push protection, and add a CI dependency-audit gate so the backlog doesn't re-accumulate. Tracked in issue #330."

## User Scenarios & Testing *(mandatory)*

The project's GitHub Security tab shows a large backlog: **88 open Dependabot alerts** (3 critical, 27 high, 39 medium, 19 low across 33 unique packages — mostly transitive dependencies and optional extras, made visible once the lockfile was committed) and **5 open CodeQL code-scanning alerts** (3 high, 2 medium). Secret scanning is disabled. A maintainer needs the backlog driven to zero unresolved critical/high alerts, with each remaining alert either fixed or explicitly dismissed-with-reason, and a guard rail that stops the backlog from re-growing. The work is split into independently-shippable slices so the low-risk bulk can land fast without waiting on the risky compatibility-sensitive bumps.

### User Story 1 - Clear the low-risk bulk and quick wins (Priority: P1) 🎯 MVP

A maintainer wants the easy, low-risk majority of alerts gone in one pass: dependency upgrades that stay within the project's current declared version ranges, plus the code-scanning findings that are either trivial config fixes or false positives. This single slice should noticeably shrink the Security tab without risking functional regressions.

**Why this priority**: This is the highest value-to-risk slice — it clears the large majority of the 88 Dependabot alerts (every package whose patched version already satisfies the project's declared constraints) and the 5 CodeQL alerts, with changes that are mechanical and verifiable against the existing test matrix. It can merge independently and immediately.

**Independent Test**: Apply the in-range dependency upgrades and the code-scanning fixes, run the full quality-gate matrix and frontend build, and confirm: (a) the Security tab's open Dependabot count drops to only the out-of-range and no-fix packages, (b) all 5 code-scanning alerts are resolved or dismissed-with-reason, and (c) no test or build regressions.

**Acceptance Scenarios**:

1. **Given** the committed dependency lockfiles, **When** dependencies are upgraded to the latest versions permitted by the project's current declared ranges, **Then** every Dependabot alert whose patched version falls within those ranges is resolved, and the full test/build suite still passes.
2. **Given** the CI workflows flagged for missing least-privilege permissions, **When** explicit minimal permission scopes are added, **Then** those code-scanning alerts are resolved and the workflows continue to run successfully.
3. **Given** the three high-severity code-scanning findings, **When** each is triaged, **Then** genuine issues are fixed and confirmed false positives or test-only findings are dismissed with a recorded justification — leaving zero unresolved high code-scanning alerts.
4. **Given** the repository's security settings, **When** secret scanning and push protection are enabled, **Then** the repository reports secret scanning as active.

---

### User Story 2 - Resolve the compatibility-sensitive major upgrades (Priority: P2)

A maintainer wants the remaining alerts whose fixes require moving a dependency past the project's currently-declared version ceiling (major-version bumps). Each of these needs the declared range widened and targeted compatibility verification because a major bump can change behavior.

**Why this priority**: These close the rest of the critical/high alerts but carry real regression risk (breaking API changes in major versions), so they must be verified individually and kept off the critical path of the P1 bulk fix. Lower priority than P1 because they are fewer alerts at higher effort.

**Independent Test**: For each package requiring a range change, widen the declared constraint, upgrade, run the affected integration/compat tests (and the frontend build for UI packages), and confirm the corresponding alert resolves with no functional regression.

**Acceptance Scenarios**:

1. **Given** a vulnerable dependency whose only patched version exceeds the project's current declared ceiling, **When** the declared range is widened and the dependency upgraded, **Then** the alert resolves and the features that use that dependency still pass their tests.
2. **Given** a major-version upgrade of a user-facing (frontend) dependency, **When** it is applied, **Then** the application still builds and its primary flows still work.
3. **Given** all P2 upgrades are complete, **When** the Security tab is reviewed, **Then** there are zero open Dependabot alerts of any severity except those with no available fix (handled in P3).

---

### User Story 3 - Handle alerts with no available fix (Priority: P3)

A maintainer wants the alerts that have **no patched version available** (a critical and a medium) to be explicitly dealt with rather than left as silent open items: trace where the dependency enters the tree, assess whether the vulnerable code path is actually reachable in this project's usage, and then either mitigate, pin, or formally dismiss-with-reason.

**Why this priority**: Cannot be fixed by upgrading, so it requires investigation and a documented risk decision rather than a code change. Lowest priority because it is a small number of alerts and the outcome may be an accepted-risk dismissal, but it is required to reach "zero unresolved" and must not be forgotten.

**Independent Test**: For each no-fix alert, produce a documented reachability assessment and a recorded decision (mitigate / pin / dismiss-with-reason), such that the alert is no longer in an undecided state.

**Acceptance Scenarios**:

1. **Given** a no-fix-available alert, **When** its dependency source and reachability are assessed, **Then** a written decision is recorded and the alert is either mitigated or formally dismissed with that justification.
2. **Given** a no-fix alert is dismissed as not-reachable, **When** the dependency later changes (becomes reachable or a fix appears), **Then** the rationale is discoverable so the decision can be revisited.

---

### User Story 4 - Prevent backlog re-accumulation (Priority: P4)

A maintainer wants automated guard rails so the backlog does not silently rebuild: routine grouped dependency-update proposals, and a CI check that fails when a new high-or-above vulnerable dependency is introduced.

**Why this priority**: Without prevention the remediation is a one-time cleanup that decays. It is lowest priority because it delivers no immediate alert reduction, but it protects the investment made in P1–P3.

**Independent Test**: Introduce (in a throwaway branch) a dependency with a known high vulnerability and confirm the CI dependency-audit check fails; confirm routine dependency-update proposals are produced on a schedule in a grouped form.

**Acceptance Scenarios**:

1. **Given** the CI pipeline, **When** a change introduces a dependency with a high-or-critical known vulnerability, **Then** the dependency-audit check fails and blocks merge.
2. **Given** the dependency-update automation, **When** new patched versions are published, **Then** grouped update proposals are raised on a regular cadence rather than one-per-package noise.
3. **Given** the audit gate runs on every pipeline, **When** the current backlog is clean, **Then** the gate passes without flagging the accepted/dismissed no-fix items.

---

### Edge Cases

- **In-range vs out-of-range fix**: an upgrade that would resolve an alert but breaks the project's declared compatibility ceiling MUST NOT be silently forced in the P1 bulk pass — it belongs to P2 with explicit range widening and compat testing.
- **Duplicate alerts for one package**: many alerts collapse onto a single dependency (e.g. one package with ~21 alerts) and onto case-variant duplicates of the same package; resolving the one upgrade MUST clear all of its alerts.
- **Test-only code-scanning findings**: a finding located in test code (not shipped/runtime code) may be dismissed as test-scope, but the dismissal MUST be recorded with that reason rather than left open.
- **False-positive code-scanning finding**: a finding where the flagged data never actually carries sensitive/untrusted data MUST be verified before dismissal, not dismissed on assumption.
- **No-fix dependency that is unreachable**: if the vulnerable code path is not reachable in this project's usage, an accepted-risk dismissal-with-reason is a valid resolution; if reachability is uncertain, it MUST be treated as reachable.
- **Audit gate vs accepted risk**: the prevention gate MUST NOT re-flag alerts that have been formally dismissed-with-reason, or it will permanently break CI.
- **Transitive-only fix unavailable**: if a transitive dependency cannot be upgraded because an intermediate package pins it, that constraint MUST be surfaced (e.g. via an override/pin or by upgrading the intermediary) rather than silently leaving the alert open.

## Clarifications

### Session 2026-06-18

- Q: How should the GitHub repo-settings actions (enable secret scanning, push protection, configure scheduled dependency updates) be delivered? → A: Automate everything reachable via the GitHub API and commit in-repo config (e.g. the scheduled-update config file); any action requiring admin rights that cannot be performed in-session MUST be documented with exact steps for the maintainer to apply.
- Q: Where should dismissal / accepted-risk justifications (false-positive code-scanning findings, no-fix dependencies) be recorded? → A: Both — a committed in-repo security decision record (e.g. `SECURITY.md` / a `docs/security/` risk-acceptances file) AND GitHub's native dismiss-with-reason, so the rationale is discoverable in-repo and survives GitHub state changes.
- Q: What is the severity bar for driving Dependabot alerts to zero? → A: All severities (critical → low) MUST reach zero open, except alerts with no available fix, each of which carries a recorded decision; there is no "best-effort" tier.
- Q: What should the CI dependency-audit prevention gate cover? → A: Both ecosystems — it MUST fail on a newly-introduced high-or-critical known vulnerability in either the Python or the frontend (npm) dependencies.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: All dependency alerts whose patched version is permitted by the project's current declared version constraints MUST be resolved by upgrading the committed dependency lockfiles, without changing those declared constraints.
- **FR-002**: After the in-range upgrades, the full existing quality-gate suite (lint, format, type-check, tests across the supported runtime matrix, coverage threshold) and the frontend build MUST pass with no regressions.
- **FR-003**: All code-scanning workflow-permission findings MUST be resolved by declaring explicit least-privilege permission scopes on the affected automation, with those workflows still running successfully.
- **FR-004**: Each high-severity code-scanning finding MUST be triaged to a terminal state — either fixed in code or dismissed with a recorded justification (e.g. confirmed false positive, or test-only scope) — leaving zero unresolved high code-scanning alerts.
- **FR-005**: Secret scanning and push protection MUST be enabled for the repository — automated via the GitHub API where permissions allow; any toggle requiring admin rights not available in-session MUST be documented with exact maintainer steps rather than silently skipped.
- **FR-006**: Dependency alerts whose only patched version exceeds the project's current declared constraints MUST be resolved by widening the declared constraint and upgrading, accompanied by targeted compatibility verification of the features that use that dependency.
- **FR-007**: After all upgradeable alerts are addressed, there MUST be zero open dependency alerts of **any** severity (critical → low) except those for which no patched version exists; there is no best-effort tier for medium/low.
- **FR-008**: Each alert with no available fix MUST be given a documented decision — a reachability assessment plus mitigate/pin/dismiss-with-reason — and MUST NOT be left in an undecided open state.
- **FR-009**: The CI pipeline MUST include a dependency-audit check, covering **both** the Python and the frontend (npm) ecosystems, that fails when a newly-introduced dependency carries a known high-or-critical vulnerability.
- **FR-010**: The dependency-audit check MUST NOT fail on alerts that have been formally dismissed-with-reason / accepted as risk.
- **FR-011**: Routine dependency-update proposals MUST be produced automatically on a regular cadence, grouped to reduce per-package noise (delivered as committed in-repo configuration where the platform supports it).
- **FR-012**: Every dismissal or accepted-risk decision (code-scanning or dependency) MUST be recorded in **both** a committed in-repo security decision record AND the platform's native dismiss-with-reason, with its justification, so it can be audited and revisited.
- **FR-013**: The remediation MUST be sequenced so the low-risk slice (FR-001…FR-005) can be reviewed and merged independently of, and earlier than, the compatibility-sensitive slice (FR-006).
- **FR-014**: Upgrades MUST preserve the reproducibility of the build — the committed lockfiles MUST remain the single source of truth and CI MUST continue to install from them deterministically.

### Key Entities

- **Dependency alert**: a reported known vulnerability in a (direct or transitive) dependency — has a severity, an affected package, a vulnerable version range, and either a patched version or none.
- **Code-scanning alert**: a static-analysis finding in the codebase — has a severity, a rule, a code location, and a state (open / fixed / dismissed-with-reason).
- **Declared constraint**: the project's stated allowable version range for a dependency; widening it is the boundary between the low-risk slice and the compatibility-sensitive slice.
- **Remediation decision**: the recorded outcome for an alert that is not simply upgraded away — fixed, mitigated, pinned, or dismissed-with-justification.
- **Prevention gate**: the automated CI check + scheduled update proposals that keep the backlog from re-accumulating.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Open alerts of **all severities** (Dependabot + code-scanning combined, critical → low) reach **zero**, except dependency alerts with no available fix, each of which has a recorded decision.
- **SC-002**: The low-risk slice alone (in-range upgrades + code-scanning fixes + secret scanning enablement) resolves the large majority of the 88 Dependabot alerts and all 5 code-scanning alerts, and merges without any test or build regression.
- **SC-003**: After remediation, the only Dependabot alerts that remain open are those requiring a declared-constraint change (handled in the P2 slice, transiently) or having no fix (handled in P3 with a recorded decision) — verifiable against the Security tab; on completion of all slices the open count is zero except recorded no-fix items.
- **SC-004**: Every package with multiple alerts collapsing onto one upgrade is fully cleared by that single upgrade (no residual alerts for an already-upgraded package).
- **SC-005**: Secret scanning is reported as enabled on the repository.
- **SC-006**: A new pull request that introduces a dependency with a known high-or-critical vulnerability is automatically blocked by the CI dependency-audit check, while a clean tree (including accepted-risk dismissals) passes it.
- **SC-007**: Every remaining open alert after the work is complete has a discoverable, recorded justification for why it remains open.

## Assumptions

- The vulnerable packages are overwhelmingly transitive or in optional extras; the small set of core runtime dependencies is largely unaffected, so most P1 fixes are lockfile-only and do not touch declared constraints.
- The two no-fix alerts (one critical, one medium) cannot be resolved by upgrading and will require a reachability-based risk decision; an accepted-risk dismissal is an acceptable terminal outcome if the vulnerable path is not reachable.
- One high code-scanning finding (clear-text logging) is suspected to be a false positive because the log statement emits only a configuration key *name*, not a secret value; this will be verified before dismissal.
- Two high code-scanning findings are located in test code and may be dismissed as test-scope or fixed cheaply.
- The project already has a committed lockfile and a CI quality-gate matrix that can serve as the regression oracle for upgrades.
- Enabling secret scanning / push protection and configuring scheduled dependency updates are repository-administration actions available to the maintainer.
- "Known high-or-critical vulnerability" for the prevention gate is judged by the same advisory data sources that feed the existing alerts.

## Dependencies

- The committed dependency manifests and lockfiles for both the backend and the frontend.
- The existing CI quality-gate matrix (lint, format, type-check, tests, coverage) and frontend build as the regression oracle.
- The repository's security configuration (alerting, secret scanning, scheduled dependency updates) and the advisory data feeding it.
- Issue #330 (the remediation plan this spec implements) and the v0.33.0 release (#328) — this work is sequenced to follow the release cut to keep the release branch clean.
