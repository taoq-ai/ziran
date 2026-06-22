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

## Structural root cause: `crewai>=0.30,<1`

The optional `[crewai]` extra pins `crewai>=0.30,<1`. CrewAI **bundles and pins** `litellm`
(~1.74) and requires `langchain*` `<1`, so the shared transitive resolution holds **litellm**
and the **entire langchain family** at old versions — their patched releases are unreachable
while crewai is present at any version it currently permits. ZIRAN's own code does **not** import
`crewai`, `chromadb`, `diskcache`, or `langgraph` (0 references), and the specific vulnerable
features below are not used. **Recommended follow-up**: evaluate dropping or loosening the
`crewai` extra (or isolating it from the audited lock), which would let ~14 of these alerts be
*fixed by upgrade* rather than accepted. Tracked as a P2 decision in spec 024.

## Code-scanning

| Alert | Location | Decision | Justification | GH reason | Date |
|---|---|---|---|---|---|
| #7 `py/clear-text-logging-sensitive-data` | `ziran/infrastructure/llm/litellm_client.py:81` | dismiss-false-positive | The `logger.warning` emits only `config.api_key_env` (the **name** of the env var), never the key value; the secret flows into `self._api_key` on a different branch and is never logged. | false_positive | 2026-06-18 |

## Dependencies — accept-risk (not reachable in ZIRAN's usage)

All rows below are **pip**, transitive via optional extras, blocked from upgrade by the crewai pin,
and the vulnerable code path is not exercised by ZIRAN. GH dismissal reason: `not_used` / `no_bandwidth` as noted.

| Alert | Package | Sev | Advisory | Why not reachable | GH reason | Revisit when |
|---|---|---|---|---|---|---|
| #109 | litellm | critical | GHSA-4xpc-pv4p-pm3w — Host-header auth bypass | litellm **proxy server** vuln; ZIRAN uses the client SDK (`acompletion`/`aembedding`), never runs the proxy | not_used | crewai loosened / litellm upgradable, or proxy adopted |
| #61 | litellm | critical | GHSA-jjhc-v7c2-5hh6 — OIDC userinfo cache key collision | proxy-server auth; client SDK not affected | not_used | as above |
| #72 | litellm | high | GHSA-v4p8-mg3p-g94g — command exec via MCP stdio test endpoints | proxy/test endpoints not run by ZIRAN | not_used | as above |
| #62 | litellm | high | GHSA-69x8-hrgq-fjj8 — password-hash exposure / pass-the-hash | proxy auth store not used | not_used | as above |
| #60 | litellm | high | GHSA-53mr-6c8q-9789 — privilege escalation via proxy config endpoint | proxy config endpoint not exposed | not_used | as above |
| #84 | chromadb | critical | GHSA-f4j7-r4q5-qw2c — pre-auth code injection | not imported by ZIRAN (0 refs); requires running the ChromaDB server, which ZIRAN never does | not_used | chromadb becomes a used dependency |
| #78 | langchain-core | high | GHSA-pjwx-r37v-7724 — unsafe `load()` deserialization | ZIRAN never calls langchain `load()` on untrusted objects (0 refs) | not_used | crewai loosened or feature used |
| #47 | langchain-core | high | GHSA-qh6h-p6c9-ff54 — path traversal in legacy `load_prompt` | `load_prompt` not used (0 refs) | not_used | as above |
| #82 | langchain | high | GHSA-3644-q5cj-c5c7 — LangSmith public-prompt-pull deserialization | ZIRAN never pulls prompts from the LangSmith hub | not_used | as above |
| #108 | langchain | medium | GHSA-gr75-jv2w-4656 — path traversal in file-search loaders | langchain file-search loaders not used | not_used | as above |
| #69 | langchain-text-splitters | medium | GHSA-fv5p-p927-qmxr — `HTMLHeaderTextSplitter.split_text_from_url` SSRF | text splitters not used (0 refs) | not_used | as above |
| #43 | langgraph | medium | GHSA-g48c-2wqr-h844 — checkpoint msgpack deserialization | ZIRAN doesn't load untrusted langgraph checkpoints (langgraph not imported) | not_used | as above |
| #42 | langgraph-checkpoint | medium | GHSA-mhr3-j7m5-c7c9 — BaseCache deserialization RCE | not reachable; no untrusted cache loading | not_used | as above |
| #41 | diskcache | medium | GHSA-w8v5-vhqr-4h9v — unsafe pickle deserialization | not imported by ZIRAN (0 refs); no untrusted cache loaded | not_used | diskcache becomes used |
| #40 | langchain-core | low | GHSA-2g6r-c272-w58r — SSRF via image token counting | image token counting not used | not_used | as above |
| #70 | langchain-openai | low | GHSA-r7w7-9xr2-qq2r — image token counting SSRF (DNS rebinding) | not used | not_used | as above |

> **Resolved by upgrade (not accepted):** `pytest` (GHSA-6w46-j5rx-g56g) was **fixed** by relaxing
> the dev cap `<9`→`<10` and bumping to 9.1.1 (full suite green) — it is not in this table.
> All in-range pip and npm alerts are likewise fixed by lockfile bump, not accepted.
