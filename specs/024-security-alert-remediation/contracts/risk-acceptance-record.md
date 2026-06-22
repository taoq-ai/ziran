# Contract: Risk-Acceptance Record

**File**: `docs/security/risk-acceptances.md` (committed)
**Satisfies**: FR-008, FR-012; clarification Q2

The in-repo source of truth for every security alert that is **not** resolved by a straight upgrade. Mirrored by GitHub's native dismiss-with-reason. Reviewed in PR.

## Required structure

A title, a short preamble, and a Markdown table. One row per dismissed/accepted alert.

```markdown
# Security Risk Acceptances

Decisions for security alerts not resolved by upgrading. Each row mirrors a
GitHub dismiss-with-reason. The `accept-risk-no-fix` pip rows below are the
authoritative source for the CI `pip-audit --ignore-vuln` suppression list.

| Advisory / Alert | Package / Location | Eco | Severity | Decision | Reachable? | Justification | GH dismissal reason | Date | Revisit when |
|---|---|---|---|---|---|---|---|---|---|
| GHSA-xxxx | chromadb | pip | critical | accept-risk-no-fix | no | <why unreachable in our usage> | won't_fix / no_bandwidth | 2026-06-18 | a patched version is published |
| GHSA-yyyy | diskcache | pip | medium | accept-risk-no-fix | no | <why unreachable> | won't_fix | 2026-06-18 | fix published |
| py/clear-text-logging-sensitive-data | ziran/infrastructure/llm/litellm_client.py:81 | codeql | high | dismiss-false-positive | n/a | logs only the env-var name, not the key value | false_positive | 2026-06-18 | the log statement changes to emit a value |
```

## Field rules

- **Decision** ∈ `{dismiss-false-positive, accept-risk-no-fix, mitigated, pinned}`.
- **Reachable?** required for dependency rows (`yes` / `no` / `unknown`); `unknown` MUST be treated as `yes` (→ cannot accept-risk; must mitigate). `n/a` for code-scanning rows.
- **GH dismissal reason** MUST match a valid GitHub dismissal reason (`false_positive`, `won't_fix`, `used_in_tests`, …) and the alert MUST actually be dismissed in GitHub with that reason.
- **Justification** MUST be specific (no "low risk" without explanation).

## Invariants

- Bijection: every row ⇔ exactly one GitHub dismissal; no orphan rows, no undocumented dismissals.
- The `accept-risk-no-fix` + `eco=pip` rows ⇔ the `pip-audit --ignore-vuln` GHSA list in CI (must not drift).
- No dependency alert with an *available* fix appears here (those are upgraded, not accepted) — enforces FR-006/FR-007.
