Verdict: PASS
Gate: security
Item: fsl-license
PR: taoq-ai/ziran#499
Head: 645303586d17ec9f46d555b2f449cd0a25f160aa
Confidence: high

## Findings
- [low] uv.lock:2 blocks: no. The lockfile `revision` drops from 5 to 3, a sign that an older uv relocked it. It has no security effect: `uv lock --check` resolves 211 packages cleanly and CI runs `--frozen`. A later relock with a newer uv will bump it back and add churn.
- [low] blocks: no. NOTICE and README carry the `<COMMERCIAL-LICENSING-CONTACT>` placeholder. This is not a security issue, and the PR body already lists it for the owner.

## Probes
- Diff scope (`git diff origin/develop...HEAD --stat`): 13 files. None of them is under `.github/workflows` and nothing under `ziran/` changed. The CI `dependency-audit` job is unchanged, with the same 7 `--ignore-vuln` ids as develop. The PR template change only adds a CLA checkbox.
- Lock scope: I filtered the uv.lock diff to changed lines that are not opentelemetry or version lines. The only one left is `revision = 5 -> 3`. Ten opentelemetry packages moved one patch (1.45.1 -> 1.45.2, 0.66b1 -> 0.66b2). `opentelemetry-exporter-prometheus` stays at 0.66b1. No package was added or removed.
- Sources: every changed package keeps `source = { registry = "https://pypi.org/simple" }`, and every URL is on files.pythonhosted.org.
- Hashes: I compared all 18 new sdist and wheel sha256 values with the PyPI JSON API (`pypi.org/pypi/<name>/<ver>/json`, digests by filename). Result: 18 OK, 0 mismatches.
- Lock consistency: `uv lock --check` in a `git archive 6453035` copy reports "Resolved 211 packages" with no drift.
- pip-audit, run as the CI command does (`uv export --frozen --no-emit-project --all-extras`, then `uvx pip-audit --no-deps --disable-pip` with the 7 CI ignores). At head: "No known vulnerabilities found, 8 ignored". With the develop base lock: "Found 1 known vulnerability", opentelemetry-api 1.45.1 CVE-2026-126360, fix 1.45.2. The bump clears the advisory.
- Supply chain: no new dependency, no install script, and no workflow or token change. The floor changes are in pyproject `otel` extras only (`opentelemetry-api` and `-sdk` `>=1.45.2,<2`), and `requires-dist` in the lock matches them.
- Secrets: the added text in LICENSE, NOTICE, CONTRIBUTING and README has no credentials or tokens. The only contact data is the existing author email in CITATION.cff, unchanged.
- No guard or parser changed, so there was nothing to mutate.
- Why confidence is high: every claim above comes from a command run at the reviewed head. What would lower it: a PyPI-side compromise of 1.45.2 itself, which hash pinning alone cannot catch.

## Residual risk
The opentelemetry 1.45.2 and 0.66b2 contents were taken on trust from the upstream PyPI release. I verified their hashes, but I did not diff their code.
