# Contract: CI Dependency-Audit Gate

**Location**: a `dependency-audit` job in the CI workflow (`.github/workflows/ci.yml`)
**Satisfies**: FR-009, FR-010; clarification Q4 (both ecosystems); SC-006

## Behaviour

| Input | Expected result |
|-------|-----------------|
| Tree with a newly-introduced **high/critical** vulnerable dependency (pip or npm) | Job **fails** → blocks merge |
| Clean tree | Job **passes** |
| Tree whose only high/critical advisories are **accepted-risk-no-fix** (recorded) | Job **passes** (suppressed) |
| New **medium/low** vulnerable dependency | Job passes (gate threshold is high+; medium/low handled by Dependabot PRs + the backlog policy, not the blocking gate) |

## Python step

```bash
# fail on high/critical; suppress only recorded accept-risk-no-fix advisories
uv export --no-emit-project --format requirements-txt > /tmp/reqs.txt   # or audit the synced env
pip-audit -r /tmp/reqs.txt \
  --ignore-vuln GHSA-<chromadb> \
  --ignore-vuln GHSA-<diskcache>
```

- The `--ignore-vuln` list MUST equal the `accept-risk-no-fix` + `eco=pip` rows in `docs/security/risk-acceptances.md` (single source of truth — see risk-acceptance-record contract).
- `pip-audit` non-zero exit ⇒ job fails.

## Frontend step

```bash
cd ui && npm audit --audit-level=high
```

- `npm audit` non-zero exit on a high/critical ⇒ job fails.
- No suppression needed today (both no-fix items are `pip`). If a no-fix **npm** advisory appears, mitigate via `package.json` `overrides` or document and raise the threshold — recorded in the risk-acceptance file.

## Constraints

- Implemented as **workflow steps invoking CLIs** — no bespoke typed Python (Constitution Principle VI; keeps it off the mypy/coverage surface).
- Runs on the same triggers as the existing CI (PRs to `develop`/`main`).
- MUST be deterministic: audits the committed lockfiles, consistent with FR-014.
