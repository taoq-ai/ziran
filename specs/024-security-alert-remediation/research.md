# Research: Security Alert Remediation

**Date**: 2026-06-18 | **Feature**: 024-security-alert-remediation

## R1 — Authoritative alert classification (in-range / out-of-range / no-fix)

**Decision**: Classify every Dependabot alert by whether its patched version satisfies the project's *current declared constraint* (direct deps) or is simply the latest lock resolution (transitive deps). This determines the P1/P2/P3 boundary precisely, replacing the rough guess in issue #330.

Computed from the live Dependabot data vs `pyproject.toml` / `ui/package.json`:

| Class | Alerts | Packages | Slice |
|-------|--------|----------|-------|
| **In-range** (lockfile bump only, no constraint change) | **79** | litellm (✅ `<2` allows 1.84.0), vite (`^7.1.7`→7.3.5), react-router (via `react-router-dom ^7.13.2`→7.15.1), python-dotenv, + all transitive (aiohttp ×21, pillow ×6, cryptography, pyjwt, urllib3, starlette, langsmith, Mako, pyasn1, requests, idna, uv, pytest, langgraph-checkpoint, langchain-text-splitters, postcss, picomatch, js-yaml, uuid, @babel/core, Pygments, …) | **P1** |
| **Out-of-range** (declared cap below fix → needs widening) | **7** | langchain (`<1`→1.3.9), langchain-core (`<1`→1.2.22), langgraph (`<1`→1.0.10), langchain-openai (`<1`→1.1.14) — the entire langchain family, all capped `<1` | **P2** |
| **No fix available** | **2** | chromadb (critical), diskcache (medium) | **P3** |

**Key correction**: `litellm` (critical, ×5 alerts), `vite`, and `react-router` are **in-range** — #330 mis-classified them as major bumps. The only genuine constraint-relaxation work is the **langchain 0.x → 1.x** family, and those four packages move together.

**Rationale**: In-range bumps carry near-zero API-break risk and are validated wholesale by the existing test matrix, so they belong in the fast P1 slice. Out-of-range bumps cross a major-version boundary (semver-breaking) and need targeted compat testing, so they are isolated to P2.

**Alternatives considered**: Forcing all fixes (incl. langchain 1.x) into one PR — rejected: couples the low-risk 90% to a high-risk 8% and blocks the quick win.

## R2 — Python dependency upgrade mechanism

**Decision**: Use `uv lock --upgrade` to refresh `uv.lock` to the latest versions permitted by the *current* `pyproject.toml` constraints; commit the lockfile. For P2, edit the langchain-family caps in `pyproject.toml` (`<1` → `<2`), then `uv lock` and `uv sync --frozen` in CI.

**Rationale**: Matches the repo's existing reproducible-CI pattern (uv.lock committed, `--frozen` syncs — PR #320). `uv lock --upgrade` respects declared ranges, so it cleanly produces exactly the in-range set without touching constraints (FR-001/FR-014).

**Alternatives**: Per-package `uv lock --upgrade-package X` — useful for surgical bumps but unnecessary when the whole in-range set is wanted at once; keep as a fallback if a blanket upgrade regresses a test.

**Transitive-pin risk**: if an intermediary pins a vulnerable transitive below its fix, surface it via a `[tool.uv]` constraint/override or by upgrading the intermediary (edge case in spec). Verify post-lock that no targeted alert remains by re-querying Dependabot.

## R3 — Frontend dependency upgrade mechanism

**Decision**: In `ui/`, run `npm update` (within existing caret ranges) and `npm audit fix` (non-breaking) to refresh `package-lock.json`; avoid `npm audit fix --force`. vite/react-router patched versions are already within the declared caret ranges, so no `package.json` edits are expected.

**Rationale**: Keeps frontend changes lockfile-only and low-risk; `--force` can pull semver-major and is explicitly avoided in P1. Validate with `npm run build` + existing UI checks.

**Alternatives**: Manual `package.json` bumps — only if a needed fix sits outside the caret range (none currently identified).

## R4 — CodeQL findings triage

| Alert | Decision | Approach |
|-------|----------|----------|
| #4, #5 `actions/missing-workflow-permissions` (`test.yml:10,46`) | **Fix** | Add top-level `permissions: { contents: read }` (least privilege) and per-job scopes where a job needs more. Harden the other workflows with the same default for consistency. |
| #7 `py/clear-text-logging-sensitive-data` (`litellm_client.py:81`) | **Dismiss as false positive** (verify first) | The `logger.warning` emits only `config.api_key_env` (the env-var *name*), not the key value; the key flows into `self._api_key` on a *different* branch. Confirm the data flow, then dismiss-with-reason in GitHub **and** record in `docs/security/risk-acceptances.md`. If verification is ambiguous, restructure the log to break the taint path instead. |
| #6 `py/insecure-temporary-file` (`test_cli_main.py:374`) | **Fix in code** | Replace insecure temp-file construction with `tempfile.NamedTemporaryFile` / the pytest `tmp_path` fixture. Fixing is cheaper than a dismissal and leaves no bookkeeping. |
| #8 `py/incomplete-url-substring-sanitization` (`test_browser_adapter.py:1430`) | **Fix in code** | Replace substring `in` URL check with an exact host/scheme comparison (`urlparse`). |

**Rationale**: Prefer fixing the two test-file findings (low effort, no residual dismissal to maintain) and dismissing only the genuine FP (#7) with a recorded justification per FR-004/FR-012.

## R5 — Secret scanning + push protection enablement

**Decision**: Enable via the GitHub REST API `PATCH /repos/{owner}/{repo}` with `security_and_analysis.secret_scanning.status = enabled` and `secret_scanning_push_protection.status = enabled`. If the token lacks admin scope, the action is documented in `quickstart.md` with the exact Settings → Code security path for the maintainer (clarification Q1).

**Rationale**: API-first automation where permission allows, graceful documentation fallback otherwise (FR-005). Secret scanning is a setting, not committed code, so it cannot live in a PR diff — only the documentation of it can.

**Alternatives**: GitHub UI only — rejected as default because it isn't reproducible/scriptable, but it is the fallback when admin rights are missing.

## R6 — CI dependency-audit gate

**Decision**: Add a `dependency-audit` job to CI covering **both** ecosystems (clarification Q4):
- **Python**: `pip-audit` against the uv-synced environment (or `uv export` → requirements), failing on high/critical. Accepted-risk no-fix advisories are suppressed via `--ignore-vuln <GHSA-ID>` (only chromadb/diskcache GHSA IDs), keeping FR-010 true.
- **Frontend**: `npm audit --audit-level=high` in `ui/`.

The gate fails the pipeline on a *newly-introduced* high/critical vuln (FR-009) and passes on a clean tree including the accepted dismissals (FR-010/SC-006).

**Rationale**: Off-the-shelf CLIs as workflow steps — no bespoke typed Python (Principle VI), so nothing enters the mypy/coverage surface. `pip-audit --ignore-vuln` is the standard accepted-risk mechanism and keeps the suppression list explicit and reviewable in the workflow.

**Alternatives**: A custom Python audit script — rejected (adds typed code + tests for no benefit). Relying solely on Dependabot alerts — rejected: alerts notify but don't *block* a PR; the spec requires a blocking gate.

**Open implementation detail (for tasks)**: `npm audit` has no clean per-advisory ignore; mitigated because the no-fix items (chromadb, diskcache) are both **pip**, so the npm side needs no suppression. If a no-fix npm advisory appears later, pin via `overrides` or raise `--audit-level`.

## R7 — Scheduled dependency updates (Dependabot config)

**Decision**: Create `.github/dependabot.yml` with three `package-ecosystem` entries — `pip`, `npm` (dir `/ui`), and `github-actions` — each on a **weekly** schedule with **grouped** updates (one PR per ecosystem per run) to reduce noise (FR-011).

**Rationale**: Grouping is the native Dependabot answer to per-package PR spam; weekly cadence balances freshness vs. churn. `github-actions` included because pinned action versions also drift.

**Alternatives**: Daily (too noisy), ungrouped (PR spam — the very problem). Renovate — heavier, not already in use; Dependabot is already the alert source.

## R8 — Risk-acceptance decision record format

**Decision**: A committed Markdown table at `docs/security/risk-acceptances.md` (clarification Q2), one row per accepted/dismissed alert: ID/advisory, package, severity, decision (dismiss-FP / accept-risk / mitigated), reachability assessment, justification, date, and the matching GitHub dismissal reason. Mirrored by GitHub's native dismiss-with-reason.

**Rationale**: In-repo discoverability that survives GitHub state changes, auditable in PR review, and the source of truth for the `pip-audit --ignore-vuln` suppression list (keeps FR-010 and FR-012 consistent — the ignore list and the doc cannot drift if both are reviewed together).

**Alternatives**: GitHub-only dismissal — not discoverable in-repo; doc-only — loses the native UI signal. Both chosen per clarification.

## R9 — langchain 0.x → 1.x compatibility (P2 risk)

**Decision**: Treat the langchain-family bump as the one genuine compatibility risk. Before widening caps, identify where `ziran` imports langchain (the `[langchain]` adapter and `[pentest]` orchestrator via `langchain-core`/`langgraph`), then run those adapters' unit + integration tests after the bump. langchain 1.0 reorganized packages (core split, deprecations); verify imports/signatures the adapter relies on still resolve.

**Rationale**: This is the only slice that can break runtime code, so it gets explicit compat verification rather than relying on the blanket matrix. Isolating it to P2 keeps the P1 win unblocked.

**Alternatives**: Pin langchain at 0.x and dismiss its alerts as accepted-risk — rejected: a patched version exists, so FR-006 requires upgrading, not accepting.

## Resolved unknowns

All Technical Context items are resolved; no `NEEDS CLARIFICATION` remain. Tooling: `uv` + `npm` (upgrades), `pip-audit` + `npm audit` (gate), Dependabot (scheduled updates), GitHub REST API (settings). No new `ziran/` runtime dependencies.
