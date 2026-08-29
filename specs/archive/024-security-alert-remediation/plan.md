# Implementation Plan: Security Alert Remediation

**Branch**: `024-security-alert-remediation` | **Date**: 2026-06-18 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/024-security-alert-remediation/spec.md`

## Summary

Drive the GitHub Security backlog to zero: **88 Dependabot alerts** + **5 CodeQL alerts**, enable secret scanning, and add a CI dependency-audit gate so it cannot re-accumulate. The work is sequenced into four independently-mergeable slices matching the spec's user stories. The authoritative alert analysis (see research.md) shows the split is **79 in-range** (lockfile-only, P1), **7 out-of-range** (the whole langchain 0.x→1.x family, P2), and **2 no-fix** (chromadb, diskcache, P3); prevention guard rails are P4.

This feature adds **no application code** to `ziran/`. It edits dependency manifests/lockfiles, GitHub Actions workflows, a new `.github/dependabot.yml`, a committed risk-acceptance record, and (where API permissions allow) repository security settings. The regression oracle is the existing quality-gate matrix.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11/3.12/3.13) backend; TypeScript 5.x / Node frontend — *no new source code*, only manifests, lockfiles, CI workflows, and docs.
**Primary Dependencies**: package managers + audit tooling — `uv` (Python lock/sync), `npm` (frontend lock), `pip-audit` (Python vuln gate), `npm audit` (frontend vuln gate). No new runtime dependencies in `ziran/`.
**Storage**: N/A (no data store). The committed risk-acceptance record (`docs/security/risk-acceptances.md`) is the only new persisted artifact.
**Testing**: existing `pytest` matrix + `ruff` + `mypy` + `npm run build` as the regression oracle; a throwaway-branch test proves the new audit gate fails on an introduced high-severity dep.
**Target Platform**: GitHub-hosted CI (Linux runners) + the GitHub repository security configuration.
**Project Type**: web (Python backend `ziran/` + React frontend `ui/`) — both ecosystems are in scope.
**Performance Goals**: N/A — the audit gate should add only seconds to CI; no runtime performance impact.
**Constraints**: lockfiles remain the single source of truth and CI installs from them deterministically (FR-014); P1 must not change declared constraints; the audit gate must not re-flag accepted-risk items (FR-010).
**Scale/Scope**: 88 + 5 = 93 alerts across 33 unique packages, 2 ecosystems; ~11 GitHub Actions workflows to harden; 1 dependabot config; 1 risk-acceptance doc.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | ✅ N/A | No application code added; no layer boundaries touched. The langchain 1.x bump (P2) only requires the existing `ziran` langchain adapter to keep passing its tests — no architectural change. |
| II. Type Safety (mypy strict) | ✅ Hold | No new Python in `ziran/`. The audit gate is implemented as CI workflow steps invoking `pip-audit`/`npm audit` CLIs — **no custom typed code** to keep it out of the mypy/coverage surface (Principle VI). Existing `mypy ziran/` must still pass after dependency upgrades. |
| III. Test Coverage ≥85% | ✅ Hold | No business logic added, so coverage should not move. FR-002 requires the existing suite (incl. coverage gate) to stay green after upgrades — that *is* the verification. |
| IV. Async-First | ✅ N/A | No I/O code added. (`requests` appears only as a vulnerable transitive dep, not in our code.) |
| V. Extensibility via Adapters | ✅ N/A | No new adapters/vectors/detectors. |
| VI. Simplicity | ✅ Pass | Audit gate uses off-the-shelf CLIs as workflow steps rather than a bespoke Python tool; no premature abstraction. |
| Quality Gates (ruff/format/mypy/pytest≥85%) | ✅ Gate | Run unchanged after every upgrade slice; this is the acceptance evidence for FR-002. |

**Result: PASS** — no violations; no Complexity Tracking entries required.

*Note*: the speckit-scaffolded branch name `024-security-alert-remediation` omits the constitution's `type/NNN-short-name` prefix, consistent with all prior speckit branches in this repo (e.g. `023-many-shot-jailbreak`). Accepted as established practice; not a code-compliance issue.

## Project Structure

### Documentation (this feature)

```text
specs/024-security-alert-remediation/
├── plan.md              # This file
├── research.md          # Phase 0 — alert analysis + tooling decisions
├── data-model.md        # Phase 1 — alert/decision/gate entities
├── quickstart.md        # Phase 1 — run-the-audit + verify steps
├── contracts/
│   ├── risk-acceptance-record.md   # schema for docs/security/risk-acceptances.md
│   ├── dependency-audit-gate.md    # CI gate behaviour contract
│   └── dependabot-config.md         # .github/dependabot.yml contract
└── tasks.md             # Phase 2 (/speckit.tasks — NOT created here)
```

### Source Code (repository root) — files this feature touches

```text
pyproject.toml                       # P2 only: widen langchain-family caps <1 → <2
uv.lock                              # P1: regenerated via `uv lock --upgrade`; P2: re-locked after cap change
ui/package.json                      # (likely untouched — vite/react-router already in-range)
ui/package-lock.json                 # P1: refreshed via `npm update` / `npm audit fix`
ziran/infrastructure/llm/litellm_client.py   # P1: verify CodeQL #7 (clear-text-logging) — likely FP, no code change
tests/unit/test_cli_main.py          # P1: CodeQL #6 insecure-temp-file — fix to tempfile API
tests/unit/test_browser_adapter.py   # P1: CodeQL #8 incomplete-url-sanitization — exact host/scheme check
.github/workflows/*.yml              # P1: add least-privilege `permissions:` blocks (CodeQL #4/#5 + harden others)
.github/dependabot.yml               # P4: NEW — grouped weekly pip + npm + github-actions updates
.github/workflows/ci.yml             # P4: NEW dependency-audit job (pip-audit + npm audit)
docs/security/risk-acceptances.md    # NEW — committed decision record (FR-012)
```

**Structure Decision**: This is a cross-cutting ops/security change, not a feature module. It lives in dependency manifests, `.github/` automation, and a docs record — no `ziran/` or `ui/src/` application code. The two ecosystems (Python `ziran/`, frontend `ui/`) are both in scope per FR-009/clarification Q4.

## Implementation Phases (slice → user story)

| Phase | Story | Scope | Alerts cleared | Risk |
|-------|-------|-------|----------------|------|
| **P1** | US1 | `uv lock --upgrade` + frontend lockfile refresh (no constraint changes); CodeQL workflow-permissions + triage the 3 highs; enable secret scanning | **79 Dependabot + 5 CodeQL** | Low — verified by existing gates |
| **P2** | US2 | Widen langchain-family caps `<1`→`<2`, re-lock, run langchain/pentest compat tests | **7** (langchain, langchain-core, langgraph, langchain-openai) | Medium — langchain 1.0 breaking changes |
| **P3** | US3 | Trace + reachability-assess chromadb (critical) & diskcache; mitigate/pin/dismiss-with-reason + record | **2** (no-fix) | Low effort, decision-heavy |
| **P4** | US4 | `.github/dependabot.yml` (grouped weekly) + CI `pip-audit`/`npm audit` gate honoring accepted-risk | prevention | Low |

P1 is the MVP and merges independently. P2/P3/P4 follow as separate PRs against `develop`.

## Complexity Tracking

> No constitution violations — section intentionally empty.
