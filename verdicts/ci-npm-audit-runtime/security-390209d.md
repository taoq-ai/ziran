Verdict: PASS
Gate: security
Item: ci-npm-audit-runtime
PR: taoq-ai/ziran#506
Head: 390209d6c1c2655544f6a42a82c1c053a2e6b2bc
Confidence: high

## Findings
- [low] .github/workflows/ci.yml:101 blocks: no. With --omit=dev, the lockfile's dev flags decide what gets audited. If someone edits ui/package-lock.json to set "dev": true on a runtime package, its advisory is hidden (probe: lodash@4.17.20 as a runtime dep exits 1, the same lockfile with that one flag edited exits 0), but npm ci still installs it and vite still bundles it. This needs a lockfile edited on purpose, which is an insider threat that an advisory gate does not defend against (CWE-1104).
- [low] .github/workflows/ci.yml:101 blocks: no. Critical and malware advisories in dev-only build tooling no longer fail CI. That tooling (vite, tailwindcss, eslint, typescript) runs in frontend-build and in release.yml's build job, whose dist/ is published to PyPI. A cheap backstop that passes at this head (exit 0, 0 critical): a second step, `npm audit --audit-level=critical`, without --omit=dev (OWASP A06/A08).
- [low] ui/package.json:13 blocks: no. "Runtime" means the dependencies block, and only by convention. A package listed under devDependencies but imported from ui/src would ship unaudited. Today no bundled package is dev (sourcemap check below). tailwindcss (dev) emits CSS only.
- [low] docs/security/risk-acceptances.md:47 blocks: no. The parent list leaves out @typescript-eslint/typescript-estree, which npm audit reports as high via tinyglobby. The section intro at line 34 still says "All rows are **pip**".

## Probes
- Head check: origin/ci/npm-audit-runtime is 390209d6c1c2655544f6a42a82c1c053a2e6b2bc. The diff has 2 files: ci.yml (+2/-1) and risk-acceptances.md (+1). All work ran in git archive copies under the scratch folder sentinel-security-ci-npm-audit-runtime.
- `npm audit --audit-level=high --omit=dev` in ui/ at the head: "found 0 vulnerabilities", exit 0. `npm audit --omit=dev --json`: 0 at every level (prod deps: 20). npm 10.9.2, registry pinned by ui/.npmrc to registry.npmjs.org.
- The old command, `npm audit --audit-level=high`, exits 1: 6 high and 8 moderate. GHSA-fc5q-39xc-vjpf (picomatch <=4.0.7, no patch, CWE-1333 ReDoS from attacker-supplied extglob patterns) is the only high root advisory. The other 5 highs (fdir, tinyglobby, vite, @vitejs/plugin-react, @typescript-eslint/typescript-estree) all come through it. The one other root advisory is minimatch GHSA-g3hv-75wg-m249, moderate, which was never gated. So --omit=dev hides no other high advisory.
- Lockfile v3: picomatch 4.0.7, fdir, tinyglobby, vite, @vitejs/plugin-react and every node the audit flags are "dev": true. picomatch's only parents are fdir, tinyglobby and vite, all dev. Of the 23 non-dev lockfile entries, none is picomatch or one of its parents.
- Shipped-bundle check: `npm ci --ignore-scripts`, then `vite build --sourcemap` into scratch. Every node_modules source in the .map files (13 packages: react, react-dom, react-router, scheduler, @tanstack/*, clsx, class-variance-authority, lucide-react, tailwind-merge, vis-network) is a runtime (non-dev) lockfile entry. grep for picomatch, tinyglobby or fdir in the dist: 0 files. Bare imports in ui/src name only runtime deps, plus the @graphstyle JSON alias and CSS `@import "tailwindcss"`.
- How Python serves the UI: hatch_build.py runs npm ci and npm run build only for wheel/sdist builds. vite outDir is ziran/interfaces/web/static (git-ignored), mounted by StaticFiles in ziran/interfaces/web/app.py:131. Only built static assets ship; no node code is on any runtime path.
- Known-positive: a copy with lodash@4.17.20 added as a runtime dep (`npm install --package-lock-only`) makes `npm audit --audit-level=high --omit=dev` exit 1 (1 high, lodash). The gate still fails on a runtime high.
- Known-negative: a copy with lodash@4.17.20 added as a devDependency exits 0 with --omit=dev and 1 with the old command, so dev-only advisories are now out of scope as intended.
- Tamper probe: in the positive copy, setting only node_modules/lodash "dev": true in the lockfile makes the audit exit 0 (finding 1).
- Workflow: the step is a static string with no expressions. ci.yml triggers on push and pull_request, with no pull_request_target, and keeps `permissions: contents: read`. release.yml's build job runs `npm ci && npm run build` with contents: read and no secrets; only the publish jobs get id-token: write. Nothing here changed.
- Residual-risk context: Dependabot security fixes are enabled (`{"enabled":true}`), but there is no Dependabot alert for GHSA-fc5q-39xc-vjpf in any state; the only open npm alert is #246, minimatch, medium. Dependabot is therefore not a proven backstop for dev-only advisories.
- Mutant: reverting the step to the old command fails at the head (exit 1 above), and the positive probe shows the threshold still bites. There is no unit test for a CI step; the dependency-audit job is the check, and it passes at the head (`gh pr checks 506`, read once). CodeQL "Analyze (actions)" also passes at the head.
- Scanner: no agent tooling changed. The repository's own scanners (npm audit, CodeQL actions) ran and are cited above.
- Confidence high: the claims come from running npm audit, lockfile flags and bundle sourcemaps at this exact head, not from the PR body. A newly published high advisory in a runtime dep would change the outcome, but that is the gate working as intended.

## Residual risk
Dev-only build tooling is no longer gated: a compromised or vulnerable vite, tailwindcss or eslint chain runs at build time in CI and in the release build, whose bundle goes to PyPI, and CI no longer fails on its advisories, malware advisories included. Picomatch itself is ReDoS from repo-controlled glob patterns, so it is not exploitable from outside.
