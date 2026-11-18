Verdict: ESCALATE
Gate: quality
Item: dep-frontend
PR: taoq-ai/ziran#489
Head: 54fc5d7ba5a9aedb2d9c93314492e7d9171d3f40
Confidence: medium
Breaking: no

## Findings
- [high] ui/package-lock.json:2877 blocks: yes. Failure: the promise "npm audit --audit-level=high passes on develop" is not met by this diff. Re-running `npm audit --audit-level=high` in a git archive of the head today (2026-11-18) exits 1 with 12 vulnerabilities (6 high): the high ones are picomatch GHSA-fc5q-39xc-vjpf (range `*`, picomatch 4.0.7 is the latest release, no patched version exists) and its dependents fdir, tinyglobby, vite, @vitejs/plugin-react (the only offered fix is the downgrade vite@6.2.7). Develop's red dependency-audit job fails on the same picomatch advisory, not on minimatch (moderate alone never trips --audit-level=high). A dependency bump cannot clear it. Whether to relax or allowlist the frontend audit gate, or accept the risk, is the owner's call (trust-boundary / goal; requirement: item promise).
- [medium] ui/package-lock.json:2877 blocks: no. minimatch GHSA-g3hv-75wg-m249 is not cleared: the lockfile still resolves node_modules/minimatch 10.2.6 under @typescript-eslint/typescript-estree 8.72.2 (advisory range typescript-eslint <=8.72.2). npm shows typescript-eslint latest 8.73.0; bumping it (not part of this group) would clear the moderate path.
- [low] blocks: no. PR checks: the green dependency-audit at this head ran 2026-11-17 09:47Z, before the picomatch advisory showed up. It printed the minimatch report and exited 0 (moderate only). A re-run now goes red, so the check does not show that develop will go green.

## Probes
- Majors: none. All 16 bumps stay inside their existing major (react 19.3.0->19.3.1, vite 8.3.4->8.3.8, lucide-react 1.55->1.73, @vitejs/plugin-react 6.1.2->6.3.0, eslint 10.12->10.15, typescript-eslint 8.71.1->8.72.2, playwright 1.64->1.65.1, and so on). package.json ranges and the 246/248-entry lockfile diff agree; `npm ci` succeeds and `npm ls --all` reports 0 invalid/missing/extraneous.
- Coverage: CI frontend-build runs `npm ci`, `npm run build` (tsc -b && vite build) and `npm run lint`, all pass. I re-ran them in a full `git archive` copy (needs ziran/interfaces/graph_style for the @graphstyle alias): build OK, lint 0 errors / 2 warnings (react-hooks/exhaustive-deps, existing). The Playwright e2e specs (@playwright/test minor bump) are not run in frontend-build; test.yml installs chromium, which I did not trace: unmeasured.
- `npm audit --audit-level=high` on develop's lockfile: rc=1, 14 vulnerabilities (6 high). At head: rc=1, 12 (6 high). The head improves the moderate count, not the high count.
- No mutation probes: no guard or branch changed. The test line is `No test: <reason>` (dependency bump).
- Simplicity: none. The diff is manifest and lockfile only; nothing deletable.

## Residual risk
Merging is safe on build and lint evidence, but it leaves develop's dependency-audit red, so the v0.43.0 PR hold stays until the owner decides how to handle the unfixable picomatch advisory (gate exception, audit allowlist, or waiting for a patched release). Recommendation: merge #489 as hygiene, bump typescript-eslint to 8.73.0, and treat the picomatch gate as an `exception:` decision.
