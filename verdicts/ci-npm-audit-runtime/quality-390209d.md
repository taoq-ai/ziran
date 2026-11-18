Verdict: PASS
Gate: quality
Item: ci-npm-audit-runtime
PR: taoq-ai/ziran#506
Head: 390209d6c1c2655544f6a42a82c1c053a2e6b2bc
Confidence: medium
Breaking: no

## Findings
- [low] docs/security/risk-acceptances.md:34 blocks: no. The intro line "All rows are **pip**, transitive via optional extras" is now false: the new picomatch row is npm. Fix: "Rows are **pip**" is not enough; the smallest accurate edit is "All rows except the npm picomatch row are **pip**". Also the ci.yml comment (about line 63-66) still says npm audit has "a known low esbuild dev-server advisory", which is now moot under --omit=dev.

## Probes
- ci.yml at 390209d parsed with ruby YAML: jobs lint, typecheck, dependency-audit, frontend-build; the npm audit step is still in dependency-audit with working-directory: ui, only the run line gained --omit=dev (diff is 1 line plus a comment).
- Ran in a git archive copy (scratch sentinel-quality-ci-npm-audit-runtime, npm ci in ui/): `npm audit --audit-level=high --omit=dev` printed "found 0 vulnerabilities", exit 0.
- Mutant (reverse the change, drop --omit=dev): `npm audit --audit-level=high` exits 1 on picomatch GHSA-fc5q-39xc-vjpf (high, chain vite > tinyglobby > fdir > picomatch). So the flag is what turns the job green.
- Guard still bites runtime: package.json has 11 runtime dependencies (react, react-router-dom, vis-network, tanstack and others); `npm ls --omit=dev --all` lists them, so --omit=dev does not audit an empty tree. picomatch appears only under devDependency vite (`npm ls picomatch --omit=dev` is empty), matching the row's claim. vite, @vitejs/plugin-react are devDependencies.
- `gh pr view 506` status check dependency-audit: COMPLETED SUCCESS at this head. Other checks (tests, frontend-build, CodeQL) were pending when read; they do not touch this diff.
- Risk-acceptance row: 7 cells under the 7-column "Alert | Package | Sev | Advisory | Why it stays | GH reason | Revisit when" table, placed in the same table; "not_used" is the GH reason value the neighbouring rows use; the Alert cell "npm audit" has no alert number (no Dependabot alert id), acceptable. The row meets acceptance 2: dev-only, review trigger a patched release.
- No test: line present in PR body (config and docs only); the dependency-audit job is the check. Rollback line present.
- Simplicity: none to delete; one flag and one table row, no new abstraction. The cheaper alternative (an ignore list) does not exist for npm audit.

## Residual risk
Dev-only high advisories are no longer gated; a new dev-tool advisory will not fail CI until someone reads Dependabot. Review trigger in the row covers picomatch only.
