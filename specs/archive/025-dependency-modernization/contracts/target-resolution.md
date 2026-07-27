# Contract: Target Resolution & Alert Disposition

**Satisfies**: FR-001, FR-006, FR-007, FR-009, FR-010

## Declared-cap changes (`pyproject.toml`)

| Dependency | From | To |
|---|---|---|
| crewai (`[crewai]`) | `>=0.30,<1` | `>=1.14,<2` |
| rich (core) | `>=13.7,<14` | `>=13.7,<15` |
| litellm (`[llm]`) | `>=1.40,<2` | `>=1.84,<2` |
| langchain (`[langchain]`) | `>=0.2,<1` | `>=1.0,<2` |
| langchain-community | `>=0.2,<1` | `>=0.4,<2` |
| langchain-openai | `>=0.1,<1` | `>=1.0,<2` |
| langchain-core (`[pentest]`) | `>=0.3,<1` | `>=1.0,<2` |
| langgraph (`[pentest]`) | `>=0.2,<1` | `>=1.0,<2` |

The regenerated `uv.lock` MUST resolve (verified: EXIT 0) and MUST be committed as the single source of truth.

## Alert disposition after the upgrade

| Alert(s) | Package | Disposition |
|---|---|---|
| #109, #61, #72, #62, #60 | litellm | **FIXED** (→1.89.3) |
| #78, #47, #40 | langchain-core | **FIXED** (→1.4.8) |
| #43 | langgraph | **FIXED** (→1.2.2) |
| #42 | langgraph-checkpoint | **FIXED** (→4.1.1) |
| #70 | langchain-openai | **FIXED** (→1.3.2) |
| #69 | langchain-text-splitters | **FIXED** (→1.1.2) |
| #82 | langchain (LangSmith prompt-pull) | **verify** at langchain 1.3.2 → fixed if patched there, else keep as not-reachable |
| #108 | langchain (file-search path traversal, GHSA-gr75) | **stays dismissed** — capped at 1.3.2 < 1.3.9 fix; unused feature (R2) |
| #84 | chromadb | stays dismissed (no fix in any version) |
| #41 | diskcache | stays dismissed (no fix) |

**Invariants**:
- Every "FIXED" alert MUST no longer be present at a vulnerable version in the lock; its dismissal row is removed from `docs/security/risk-acceptances.md` and its GHSA from the CI `--ignore-vuln` list.
- The kept-dismissed rows (#108 if unfixed, chromadb, diskcache) remain in both the record and the ignore list.
- After reconciliation the ignore list == the kept-dismissed pip GHSAs (no orphans).
- **Zero new alerts** of any severity introduced by the upgraded set (FR-009) — enforced by the `dependency-audit` gate.
