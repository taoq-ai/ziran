Verdict: PASS
Gate: security
Item: G6-RELEASE
PR: taoq-ai/ziran#530
Head: 0388a666c04f34b0924e1748d85cc2f80dbb7798
Confidence: high

## Findings
- [low] blocks: no. Dependabot alert #246 (minimatch GHSA-g3hv-75wg-m249, medium, dev scope) sits on ui/package-lock.json, which exists only on main; develop (default branch) and this head have no ui/ tree, and it is not shipped in the wheel or sdist. It should auto-close once main takes this merge; dismiss it as "no longer used" if it does not.
- [low] .github/workflows/ci.yml:90 blocks: no. Stale ignore: `--ignore-vuln GHSA-w8v5-vhqr-4h9v` (diskcache) matches nothing because diskcache is no longer in the all-extras export (0 lines). The risk-acceptances.md row #41 is stale too. Drop both in a follow-up.
- [low] blocks: no. Existing gap, not changed here: the `pypi` and `testpypi` environments have no protection rules or deployment branch/tag policy (gh api environments). The OIDC publish is gated only by the verify-tag job (tag must be an ancestor of origin/main) plus the PyPI trusted-publisher binding. A required reviewer or a `v*` tag policy on `pypi` would add a second guard.
- [low] .github/workflows/release.yml:51 blocks: no. Existing gap, not changed here: `${{ env.RELEASE_TAG }}` (fed by the workflow_dispatch `tag` input) is expanded inline in `run:` scripts. Only users with write access can reach it, and that job has a read-only token, so it is low risk. Passing the tag through `env:` and quoting `"$RELEASE_TAG"` would close it (CWE-78).

## Probes
- Per-merge gates, v0.43.0..0388a66 first-parent: #514 security PASS at 360a0e7 = merged head; #517 PASS 2083c50 = head; #518 PASS 2e1d454 = head; #524 PASS 6963fdd = head (earlier FIX at b252b75 superseded); #525 PASS 28f42d8 = head; #526 PASS b993da9 = head. No security gate was needed for #481 (uv.lock langgraph bump, covered by the pip-audit below), #516 (test only), #519 (docs/arch), #528 (docs) or #515 (main back-merge). Each merged headRefOid was checked with gh pr view.
- Diff of release-relevant config, origin/main..0388a66 (.github, pyproject.toml, uv.lock): release.yml only drops the setup-node and `npm ci && npm run build` steps. publish-pypi is unchanged: environment pypi, `id-token: write` only on that job, top-level `permissions: contents: read`, pypa/gh-action-pypi-publish@release/v1 with no API token. The ci.yml npm audit and frontend-build jobs are gone, dependabot has no npm entry, the `ui` extra is removed, the hatch custom build hook (hatch_build.py) is removed, and `streaming` (websockets) plus `autogen-ext[openai]` were added and already gated in #525 and #517. fastapi/uvicorn are now in the test group only.
- pip-audit, CI-identical, in a git archive copy: `uv export --frozen --no-emit-project --all-extras` gave 4332 lines; `uvx pip-audit -r ... --no-deps --disable-pip` with the 7 CI ignores ran with rc=0: "No known vulnerabilities found, 8 ignored". The same run without ignores (rc=1) lists only chromadb 1.5.9 x4 (GHSA-f4j7, -36p7, -2wm9, -xph7; no fix exists), langchain 1.3.2 GHSA-gr75 and langsmith 0.8.5 GHSA-f4xh. Each one matches a risk-acceptances.md row (#84, #148, #147, #146, #108, #111).
- Dependabot open alerts (gh api, read once): 4 open. #146, #147 and #148 are chromadb (pip, runtime, via crewai's optional memory), have no patched version, and are accepted in docs/security/risk-acceptances.md rows 44-46. Nothing in ziran's own wheel pulls them in; they come only with the crewai extra. #246 is npm minimatch on ui/package-lock.json, dev scope, and does not affect 0.44.0 (see the first finding).
- Wheel/sdist built from the git archive copy with SETUPTOOLS_SCM_PRETEND_VERSION=0.44.0 `uv build` (rc=0): ziran-0.44.0-py3-none-any.whl, 264 entries. No interfaces/web, /ui/, .js, .css, .html, .map, .tsx, .svg, font or static/ files, and no web imports or ZIRAN_DATABASE_URL in the wheel's code. METADATA has Version 0.44.0, the Provides-Extra list has no `ui`, and there are no fastapi/sqlalchemy/asyncpg/alembic/psycopg/uvicorn Requires-Dist lines.
- Secret pattern scan (AWS, OpenAI/Anthropic sk-, ghp_/github_pat_, Slack, PEM private keys, Google AIza, HF, PyPI, Stripe) over the unpacked wheel and sdist. The wheel has one hit, the canary `sk-00000000-0000-0000-0000-000000000001` in a2a_attacks.yaml. The sdist hits are truncated or example fixtures in tests/, benchmarks/ground_truth and examples (***, `MIIEpAIBAAKCAQEA`, `b3BlbnNzaC1rZXktdjEAAAAA...`). .env.example holds only placeholders and lost the DB URL comment. The sdist has no .env, .wuwei, .claude/ or ui/.
- The repository has no secret scanner of its own (no gitleaks, trufflehog or detect-secrets in .github or on PATH), so the repo-scanner check is unmeasured; the pattern scan above is the substitute.
- Dockerfile copies only pyproject.toml, README.md, LICENSE, NOTICE and ziran/, with no ui or npm steps.
- No processes left running (pgrep on the scratch path is empty).
- Confidence is high because every claim comes from a command run at this exact head (archive build, CI-identical audit, gh api reads). It would drop if the PyPI trusted-publisher binding changed outside the repo, which this gate cannot see.

## Residual risk
The chromadb advisories have no fix and stay accepted. Publish safety rests on verify-tag plus the PyPI trusted-publisher binding, since the pypi environment has no protection rules.
