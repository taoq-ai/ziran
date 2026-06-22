# Quickstart: Security Alert Remediation

**Feature**: 024-security-alert-remediation | **Date**: 2026-06-18

Per-slice verification mapped to the spec's Success Criteria. Each slice is a separate PR against `develop`.

## Prerequisites

```bash
uv sync --frozen           # backend env from the committed lockfile
cd ui && npm ci && cd ..   # frontend env from the committed lockfile
```

## P1 — Low-risk bulk (US1) → SC-002, SC-004, SC-005

```bash
# 1. Refresh Python lockfile within current constraints (in-range fixes only)
uv lock --upgrade
uv sync --frozen

# 2. Refresh frontend lockfile (non-breaking)
cd ui && npm update && npm audit fix && cd ..   # NOT --force

# 3. CodeQL fixes: add permissions blocks to workflows; fix the 2 test-file findings;
#    verify #7 is a false positive, dismiss-with-reason, add a row to docs/security/risk-acceptances.md

# 4. Regression oracle MUST stay green
uv run ruff check . && uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran          # all pass, coverage >= 85%
cd ui && npm run build && cd ..

# 5. Enable secret scanning + push protection (admin token; else document for maintainer)
gh api -X PATCH repos/taoq-ai/ziran \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
```

**Pass when**: gates green, `npm run build` ok, the in-range Dependabot alerts (79) drop off, all 5 CodeQL alerts resolved/dismissed, secret scanning shows enabled.

## P2 — langchain 0.x → 1.x (US2) → SC-001, SC-003

```bash
# Widen the langchain-family caps in pyproject.toml: <1  ->  <2 for
#   langchain, langchain-community, langchain-openai, langchain-core, langgraph
uv lock && uv sync --frozen

# Targeted compat verification of the langchain adapter + pentest orchestrator
uv run pytest -m "unit or integration" -k "langchain or pentest" -v
uv run mypy ziran/ && uv run pytest --cov=ziran
```

**Pass when**: the 7 out-of-range alerts resolve and the langchain/pentest paths still pass.

## P3 — No-fix packages (US3) → SC-007

```bash
# Trace where chromadb / diskcache enter the tree
uv pip tree 2>/dev/null | grep -iE "chromadb|diskcache" || uv tree | grep -iE "chromadb|diskcache"
```

Assess reachability in our code paths; for each: mitigate/pin, or dismiss-with-reason in GitHub **and** add a row to `docs/security/risk-acceptances.md`. The pip `accept-risk-no-fix` rows become the `pip-audit --ignore-vuln` list.

**Pass when**: chromadb + diskcache are no longer undecided; each has a recorded decision.

## P4 — Prevention (US4) → SC-006

```bash
# Local dry-run of the gate
uv export --no-emit-project --format requirements-txt > /tmp/reqs.txt
pip-audit -r /tmp/reqs.txt --ignore-vuln <GHSA-chromadb> --ignore-vuln <GHSA-diskcache>
cd ui && npm audit --audit-level=high && cd ..
```

Add `.github/dependabot.yml` (grouped weekly, 3 ecosystems) and the `dependency-audit` CI job.

**Verify the gate bites**: on a throwaway branch, pin a known-vulnerable high-severity dependency and confirm the `dependency-audit` job **fails**; revert.

**Pass when**: gate fails on an introduced high/critical, passes on the clean tree (incl. accepted dismissals); Dependabot validates the config with no error.

## Final acceptance (all slices) → SC-001, SC-007

```bash
gh api "repos/taoq-ai/ziran/dependabot/alerts?state=open&per_page=100" --jq 'length'        # → 0 (or only recorded no-fix)
gh api "repos/taoq-ai/ziran/code-scanning/alerts?state=open&per_page=100" --jq 'length'      # → 0
```

Every still-open alert has a discoverable row in `docs/security/risk-acceptances.md`.
