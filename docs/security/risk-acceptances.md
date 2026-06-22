# Security Risk Acceptances

Decisions for security alerts that are **not** resolved by upgrading a dependency.
Each row mirrors a GitHub dismiss-with-reason (code-scanning or Dependabot), so the
rationale is discoverable in-repo and survives GitHub state changes.

The `accept-risk-no-fix` / `accept-risk-not-reachable` rows with **Eco = pip** are the
authoritative source for the CI `pip-audit --ignore-vuln` suppression list (see
`.github/workflows/ci.yml` → `dependency-audit`). Keep the two in sync.

Conventions:
- **Decision** ∈ `dismiss-false-positive` | `accept-risk-not-reachable` | `accept-risk-no-fix` | `mitigated` | `pinned`.
- **Reachable?** is required for dependency rows (`no` here means the vulnerable code path is
  not exercised by ZIRAN; `unknown` MUST be treated as `yes` — cannot accept-risk, must mitigate).
- The **GH dismissal reason** column must match the reason actually selected in GitHub.

## History: the crewai-pinned cluster was upgraded (spec 025)

Spec 024 dismissed ~16 litellm + langchain-family advisories as not-reachable because
`crewai>=0.30,<1` transitively pinned them at vulnerable versions. **Spec 025 (#332 Option C)**
forward-modernized the stack — `crewai 1.14.7`, `rich 14.3.4`, `litellm 1.89.3`, `openai 2.43`,
`langchain-core 1.4.8`, `langgraph 1.2.2` — so **those advisories are now fixed by upgrade**, not
accepted. Only the four rows below remain, each with **no reachable fix** in the resolved tree.

## Code-scanning

| Alert | Location | Decision | Justification | GH reason | Date |
|---|---|---|---|---|---|
| #7 `py/clear-text-logging-sensitive-data` | `ziran/infrastructure/llm/litellm_client.py:81` | dismiss-false-positive | The `logger.warning` emits only `config.api_key_env` (the **name** of the env var), never the key value; the secret flows into `self._api_key` on a different branch and is never logged. | false_positive | 2026-06-18 |

## Dependencies — accept-risk (no reachable fix)

All rows are **pip**, transitive via optional extras, and the vulnerable code path is not
exercised by ZIRAN. Each either has no fixed version anywhere, or its fix is unreachable in the
spec-025 resolution (the package caps below its patched line, and the feature is unused).

| Alert | Package | Sev | Advisory | Why it stays | GH reason | Revisit when |
|---|---|---|---|---|---|---|
| #84 | chromadb | critical | GHSA-f4j7-r4q5-qw2c — pre-auth code injection | **No fixed version exists** (affects chromadb 1.0.0–1.5.9). Transitive via crewai's optional memory backend, but the CrewAI adapter runs with memory disabled and never starts the ChromaDB server the vuln requires. | not_used | a fixed chromadb is published / memory enabled |
| #41 | diskcache | medium | GHSA-w8v5-vhqr-4h9v — unsafe pickle deserialization | **No fixed version exists.** 0 refs in ZIRAN; no untrusted cache is loaded. | not_used | a fixed diskcache is published / diskcache becomes used |
| #108 | langchain | medium | GHSA-gr75-jv2w-4656 — path traversal in file-search loaders | Fixed in langchain `1.3.9`, but the spec-025 tree **caps `langchain` at 1.3.2** (flooring `>=1.3.9` is unsatisfiable); langchain file-search loaders are not used by ZIRAN. | not_used | langchain resolves to ≥1.3.9 |
| #111 | langsmith | high | GHSA-f4xh-w4cj-qxq8 — LangSmith SDK TracingMiddleware arbitrary server-side file read | Fixed in langsmith `0.8.18`, but the tree **caps `langsmith` at 0.8.5**; ZIRAN does not use the LangSmith SDK / TracingMiddleware (0 refs). | not_used | langsmith resolves to ≥0.8.18 |

> **Resolved by upgrade (not accepted):** the litellm advisories (×5, incl. 2 critical),
> langchain-core (×3), langgraph, langgraph-checkpoint, langchain-openai, langchain-text-splitters,
> and the langchain LangSmith-prompt-pull advisory (#82) were all **fixed by the spec-025 upgrade**
> — removed from this table. `pytest` (GHSA-6w46) and the in-range pip/npm alerts were fixed by
> lockfile bump in spec 024.
