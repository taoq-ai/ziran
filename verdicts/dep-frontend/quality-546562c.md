Verdict: PASS
Gate: quality
Item: dep-frontend
PR: taoq-ai/ziran#489
Head: 546562c2f50bbc6a6764d4c2ac834f91ebc3dd9f
Confidence: medium
Breaking: no
Supersedes: dep-frontend/quality-54fc5d7.md

## Findings
none

## Probes
- closed: picomatch GHSA-fc5q-39xc-vjpf unmet promise at 546562c. The owner chose the runtime-scoped audit (#506, bd78aff, an ancestor of this head). The ci.yml line 101 now reads `npm audit --audit-level=high --omit=dev`, and docs/security/risk-acceptances.md:47 records the picomatch acceptance with its revisit trigger.
- Fresh `git archive 546562c` copy: `npm ci` OK; `npm audit --audit-level=high --omit=dev` prints "found 0 vulnerabilities", rc=0. The unscoped `npm audit --audit-level=high` still exits 1, as the risk acceptance expects.
- Lockfile: `npm ls --all` shows 0 invalid/missing/extraneous. ui/package.json is unchanged from the previously reviewed head (same 16 in-major bumps, no majors); the rest of the head-to-head diff is the rebase onto develop.
- `npm run build` (tsc -b and vite build) OK; `npm run lint` 0 errors, 2 existing warnings.
- PR checks at this head: dependency-audit pass, frontend-build pass, lint pass, typecheck pass, test 3.11/3.12/3.13 pass, integration-test pass, detection-accuracy-gate pass, pentest-eval-gate pass; CodeQL skipping.
- No mutants: no guard or branch changed; `No test:` line is correct for a manifest and lockfile bump.
- Simplicity: none; the diff is manifest and lockfile only.
- note, blocks: no: minimatch GHSA-g3hv-75wg-m249 (moderate, dev-only) is still in the full tree (minimatch 10.2.6 under typescript-estree 8.72.2). typescript-eslint 8.73.0 would clear it. It does not affect the runtime-scoped gate.
- note, blocks: no: the Playwright e2e specs are not run in frontend-build; unmeasured for the @playwright/test minor bump.

## Residual risk
Dev-only build tooling carries the unfixed picomatch ReDoS; it is accepted by the owner and revisited when a patched picomatch is published. The e2e suite is not exercised against the new Playwright.
