Verdict: PASS
Gate: security
Item: G2-RELEASE
PR: taoq-ai/ziran#511
Head: e62731600fc9c0461eebffed0026cdae5851cbcf
Confidence: medium

## Findings
- [medium] blocks: no. 21 PRs that ship in 0.43.0 have no WUWEI security verdict and no ledger entry: #464-#469, #471, #474, #480, #484, #485, #487, #488, #490-#497 (merged 2026-10-10 to 2026-11-13, outside WUWEI). This gate reviewed their shipped-code and workflow diffs (see Probes) and found no defect, but that is a release-level read, not a per-PR gate.
- [low] .github/workflows/release.yml:185 blocks: no. The `pypi` environment has no protection rules and no deployment branch policy (gh api environments/pypi). Publishing rests on the verify-tag job in the same file, so anyone with write access who dispatches release.yml from a branch with an edited copy can skip it and publish through OIDC. This is not new in this release. Fix: add a required reviewer, or limit deployments to v* tags.
- [low] pyproject.toml:69 blocks: no. Dependabot #234 (langgraph GHSA-3fx2-cqw9-xr3c, medium) is open on develop. uv.lock pins langgraph 1.2.4 with langgraph-sdk 0.4.6, the patched SDK; ziran never uses RemoteGraph or langgraph_sdk, so it is not exploitable. pip-audit does not report it, and docs/security/risk-acceptances.md has no row for it. Bump langgraph in the lock to 1.2.14 or later to close the alert.
- [low] blocks: no. Dependabot #146-#148 (chromadb, 1 critical and 2 high, no fixed version) are on develop, the default branch, so they cover what 0.43.0 ships. They are accepted in risk-acceptances.md rows #146-#148 and ignored in CI. PyPI users who install ziran[crewai] or ziran[all] still get chromadb through crewai, whatever uv.lock says.
- [low] .github/workflows/release.yml:151 blocks: no. Existing supply-chain shape: `npm ci` runs package install scripts in the same job that builds the wheel; actions are pinned by tag, not SHA; pypa/gh-action-pypi-publish is pinned to the release/v1 branch. None of this changed since v0.42.0.
- [low] pyproject.toml:149 blocks: no. The mcp override comment is stale. `uv pip compile` of crewai>=1.14,<2 with mcp>=1.30,<2 resolves crewai 1.15.41 and mcp 1.30.0, so PyPI users get the CVE-2026-59951 fix without the override.

## Probes
- Scope: first-parent origin/main..e627316 has 36 PR merges since v0.42.0 (b813e4f) and 0 non-merge commits. Every commit comes from a PR.
- Security PASS at merge head: #505 (0137433), #506 (390209d), #499 (6453035), #470 (3f5390e).
- PASS at an earlier head, with the PR's own later commits read here: #502 (24b1f19 -> e30ae70: 10-line adapter change plus a mypy override); #507 (6838a92 -> 715e089: 6 lines that remove metadata); #503 (474e866 -> d7caa9c: a develop merge only); #509 (3b8aabb -> ee4e6b6: workflow path filter, a per-PR concurrency group, upload continue-on-error; the comment job keeps env-passed values and pull-requests: write only on pull_request, so there is no injection path); #510 (ae73435 -> 68cd369: benchmark baseline and tests, not shipped).
- Needed none: #504 and #508 (vector and CVE YAML plus tests), #479, #489, #466, #467, #474, #487, #488 (lockfile bumps, covered by the audits below), #500 (docs), #501 (PoC template: f-string to str.format with the same fields; substituted values are not re-expanded).
- Ungated PRs, shipped-code read: #493 and #495 strip the reserved provenance and judge metadata keys at HttpAgentAdapter (invoke and stream) and at AttackExecutor (every adapter), which covers the new openai-agents and autogen adapters. #491 replay_client.py: O_NOFOLLOW, held dir fd, regular file with one link, unit and key regexes, no text in errors. #494: a hybrid share above 0 is refused in `ziran scan`, so no model call is reachable. #471: plugin SKILL untrusted-content rule, action pinned to a SHA. #469, #485 and #491 workflows: env-passed refs, no pull_request_target or workflow_run in any workflow.
- Mutant: drop_reserved returns the metadata unchanged (copy at e627316). 6 tests fail, among them tests/unit/test_reserved_metadata.py::test_executor_invoke_drops_reserved_keys and tests/unit/test_http_adapter.py::TestHttpAgentAdapter::test_invoke_drops_target_supplied_provenance_keys. Killed.
- ReDoS probe of provenance.atoms() on 10 adversarial strings of 20k to 104k chars (dot, dash, @ and digit runs, nested domains, repeated http://): each took 0.007 s or less, so time is linear.
- pip-audit, as CI runs it (uv export --frozen --all-extras --no-emit-project; uvx pip-audit --no-deps --disable-pip with the 7 CI ignores): "No known vulnerabilities found, 8 ignored". Without ignores: 8 findings (chromadb x5, langchain x2, langsmith x1), all on accepted rows.
- npm audit in ui/ (copy): --omit=dev --audit-level=high gives "found 0 vulnerabilities". The full audit gives 6 moderate and 6 high, all dev-only (picomatch accepted, minimatch GHSA-g3hv dev).
- Dependabot (read once): default branch is develop; 5 open alerts: #246 minimatch (medium, development), #234 langgraph (medium), #146-#148 chromadb (high, high, critical). None is main-only. All are lock-level on develop; the wheel ships version ranges.
- Release path: release.yml and release-please.yml are unchanged against main (git diff --stat), the same files that cut v0.42.0. PyPI publishes through OIDC trusted publishing with id-token: write only in publish-pypi; secrets used are RELEASE_PAT (release-please) and GITHUB_TOKEN. The wheel packages only ziran/ plus the built UI.
- PR #511 checks (read once): all pass except integration-test (3.11 run), still pending.
- Confidence medium: the 21 ungated PRs got a release-level read of their trust paths, not a full per-PR gate; the PyPI trusted-publisher settings are not visible from here (unmeasured).

## Residual risk
The ungated PRs since v0.42.0 got one release-level security read, not per-PR gates. The unprotected pypi environment lets any repository writer publish.
