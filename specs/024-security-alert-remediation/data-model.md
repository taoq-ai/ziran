# Data Model: Security Alert Remediation

**Date**: 2026-06-18 | **Feature**: 024-security-alert-remediation

This feature introduces no runtime/domain data models (no `ziran/` Pydantic entities). The "entities" below are the **artifacts and records** the work produces, with their fields and the rules that govern them. The only persisted new artifact is the risk-acceptance record.

## Entity: Dependency Alert (external — GitHub/Dependabot)

A known-vulnerability report on a direct or transitive dependency. Read-only input; not stored by us.

| Field | Meaning |
|-------|---------|
| `package`, `ecosystem` | the affected dependency and registry (`pip` / `npm`) |
| `severity` | critical / high / medium / low |
| `vulnerable_range`, `first_patched_version` | the version math driving classification |
| `classification` (derived) | `in-range` \| `out-of-range` \| `no-fix` (per research R1) |
| `state` | open → fixed (upgrade) \| dismissed-with-reason (no-fix/accepted) |

**Rules**:
- `in-range` ⇒ resolved by lockfile upgrade only, no constraint change (P1).
- `out-of-range` ⇒ resolved by widening the declared constraint + upgrade + compat test (P2).
- `no-fix` ⇒ must reach a recorded decision; never left undecided (P3, FR-008).
- Multiple alerts on one package are cleared together by that package's single upgrade (FR-004/SC-004).

## Entity: Code-Scanning Alert (external — CodeQL)

| Field | Meaning |
|-------|---------|
| `rule`, `location` | the CodeQL rule id + file:line |
| `severity` | high / medium |
| `resolution` | `fixed-in-code` \| `dismissed(false-positive)` \| `dismissed(test-scope)` |

**Rules**: every high MUST reach a terminal resolution (FR-004). Dismissals MUST be recorded (FR-012). Test-only findings may be fixed or dismissed-with-reason; genuine FPs MUST be verified before dismissal.

## Entity: Risk-Acceptance Record (NEW — committed)

The single new persisted artifact: `docs/security/risk-acceptances.md`. One row per alert that is **not** simply upgraded away. Full schema in [contracts/risk-acceptance-record.md](contracts/risk-acceptance-record.md).

| Field | Required | Notes |
|-------|----------|-------|
| Advisory / Alert ID | ✅ | GHSA / CVE / CodeQL rule + alert number |
| Package / Location | ✅ | dependency name or file:line |
| Severity | ✅ | |
| Decision | ✅ | `dismiss-false-positive` \| `accept-risk-no-fix` \| `mitigated` \| `pinned` |
| Reachability assessment | ✅ (deps) | is the vulnerable path reachable in our usage? |
| Justification | ✅ | why this decision is safe |
| GitHub dismissal reason | ✅ | the matching native dismissal reason (kept in sync) |
| Date / Reviewer | ✅ | |
| Revisit trigger | optional | condition under which to re-open (e.g. "fix published", "dep becomes reachable") |

**Rules**:
- Every GitHub dismissal has a corresponding row, and vice-versa (FR-012 — both records stay in sync).
- The set of `accept-risk-no-fix` rows whose ecosystem is `pip` defines exactly the `pip-audit --ignore-vuln` suppression list (keeps FR-010 ⇄ the gate honest).

## Entity: Dependency-Audit Gate Config (NEW — CI)

CI job config covering both ecosystems. Contract in [contracts/dependency-audit-gate.md](contracts/dependency-audit-gate.md).

| Field | Meaning |
|-------|---------|
| `python_audit` | `pip-audit` invocation + `--ignore-vuln` suppression list |
| `frontend_audit` | `npm audit --audit-level=high` in `ui/` |
| `fail_threshold` | high or critical ⇒ fail the pipeline |
| `suppressions` | sourced from the `accept-risk-no-fix` pip rows (FR-010) |

**State transition**: PR introduces high/critical dep → gate `fail` (blocks merge). Clean tree (incl. accepted dismissals) → gate `pass`.

## Entity: Scheduled-Update Config (NEW — `.github/dependabot.yml`)

Contract in [contracts/dependabot-config.md](contracts/dependabot-config.md).

| Field | Value |
|-------|-------|
| ecosystems | `pip` (`/`), `npm` (`/ui`), `github-actions` (`/`) |
| schedule | weekly |
| grouping | one grouped PR per ecosystem per run (FR-011) |

## Relationships

```text
Dependency Alert ──classified──> {in-range→P1 | out-of-range→P2 | no-fix→P3}
        │ no-fix / accepted
        └────────────> Risk-Acceptance Record ──defines──> Audit-Gate suppression list
Code-Scanning Alert ──dismissed──> Risk-Acceptance Record
Scheduled-Update Config ──prevents──> new Dependency Alerts
Audit-Gate Config ──blocks──> new high/critical Dependency Alerts (except suppressed)
```
