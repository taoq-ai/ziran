# Tasks: Security Alert Remediation

**Input**: Design documents from `/specs/024-security-alert-remediation/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: No bespoke unit/integration tests are added — this feature ships **no application logic**. Verification is the **existing** quality-gate matrix (ruff/format/mypy/pytest≥85% + `npm run build`) as the regression oracle (FR-002), plus a throwaway-branch "gate-bites" check for the new CI audit gate (SC-006). This matches Constitution III (coverage must stay ≥85%, not grow new tests for non-logic changes).

**Organization**: Tasks grouped by user story (US1 P1 → US4 P4) so each is an independently-mergeable PR against `develop`.

> **Implementation findings (2026-06-18, during P1)** — the lock upgrade reclassified four packages and surfaced one environment block:
> - **litellm (CRITICAL)** is bundled+pinned by `crewai` (even crewai's newest in-range `0.203.2` holds litellm at `1.74.9`). The advisory is a litellm **proxy-server** Host-header auth bypass; ZIRAN uses litellm as a **client library**, so it is most likely **not reachable** → moves to **P3** (reachability dismissal) unless we bump `crewai` past `<1` (large compat risk).
> - **langchain / -core / -openai / langgraph / -text-splitters / langgraph-checkpoint** stay at 0.3.x even with caps widened to `<2` — held by the `crewai` + `langchain-community` coupling. **P2 is bigger than a cap bump** (likely needs a `crewai` major bump too).
> - **pytest** is held by our own `pytest>=8.0,<9` cap → **P2** decision (relax to `<10` or keep; the alert is medium).
> - **numpy** was bumped 2.4.2→2.5.0 by the blanket upgrade and broke `mypy` (PEP 695 `type` stubs vs py3.11 target); **pinned back to 2.4.2** (no security need). Edge case "transitive upgrade breaks a gate" — handled.
> - **T009 (frontend npm)** is **blocked in this environment** (npm registry returns 403); must run in CI or on a maintainer machine.

## Path Conventions

Python backend at repo root (`pyproject.toml`, `uv.lock`, `ziran/`); frontend in `ui/`; automation in `.github/`; decision record in `docs/security/`.

---

## Phase 1: Setup

**Purpose**: Capture the starting state so the post-remediation drop is verifiable.

- [X] T001 Record the baseline open-alert inventory in the tracking PR description: 88 Dependabot (by class — **79 in-range**, **7 out-of-range** [langchain family], **2 no-fix** [chromadb, diskcache]) and **5 CodeQL** (#4/#5 workflow-permissions, #6/#8 test-file, #7 clear-text-logging FP), per research.md R1.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The committed decision record that US1 (FP dismissal) and US3 (no-fix) both write into, and that the US4 audit-gate suppression list reads from. **Must exist before any alert is dismissed.**

- [X] T002 Create `docs/security/risk-acceptances.md` with the preamble + table schema from `contracts/risk-acceptance-record.md` (columns: Advisory/Alert, Package/Location, Eco, Severity, Decision, Reachable?, Justification, GH dismissal reason, Date, Revisit when). Note in the preamble that the `accept-risk-no-fix` + `eco=pip` rows are the source of truth for the CI `pip-audit --ignore-vuln` list.

**Checkpoint**: decision record exists — dismissals can now be recorded.

---

## Phase 3: User Story 1 — Low-risk bulk + quick wins (Priority: P1) 🎯 MVP

**Goal**: Clear the 79 in-range Dependabot alerts and all 5 CodeQL alerts, enable secret scanning — no constraint changes, no regressions.

**Independent Test**: After this PR, the in-range Dependabot alerts drop off, all 5 CodeQL alerts are resolved/dismissed, secret scanning shows enabled, and the full gate matrix + frontend build pass.

- [X] T003 [P] [US1] Add least-privilege `permissions:` to `.github/workflows/test.yml` (top-level `permissions: { contents: read }`, per-job scopes where needed) — resolves CodeQL #4 (L10) and #5 (L46).
- [X] T004 [P] [US1] (Already satisfied — 10/11 workflows already declared permissions; only test.yml needed it, done in T003) Add a default least-privilege `permissions:` block to the remaining workflows for consistency: `.github/workflows/{ci,benchmark,detection-accuracy,docs,pentest-eval,action-test,lint-ci-templates,policy-refresh-selftest,release-please,release}.yml` (grant only the scopes each actually needs).
- [X] T005 [P] [US1] Fix CodeQL #6 (`py/insecure-temporary-file`) in `tests/unit/test_cli_main.py:374` — replace insecure temp-file construction with `tempfile.NamedTemporaryFile` or the pytest `tmp_path` fixture.
- [X] T006 [P] [US1] Fix CodeQL #8 (`py/incomplete-url-substring-sanitization`) in `tests/unit/test_browser_adapter.py:1430` — replace substring `in` URL check with exact host/scheme comparison via `urllib.parse.urlparse`.
- [X] T007 [US1] Verify CodeQL #7 (`py/clear-text-logging-sensitive-data`) at `ziran/infrastructure/llm/litellm_client.py:81` is a false positive (logs only `config.api_key_env`, the env-var name, not the key); dismiss-with-reason `false_positive` in GitHub AND add the row to `docs/security/risk-acceptances.md`. If the data flow is ambiguous, restructure the log line to break the taint path instead.
- [~] T008 [US1] (Python in-range cleared; litellm/pytest/langchain stragglers reclassified to P2/P3 — see findings) Refresh the Python lockfile within current constraints: `uv lock --upgrade` then `uv sync --frozen`; commit `uv.lock`. Clears the 79 in-range pip alerts (litellm, aiohttp ×21, pillow, cryptography, pyjwt, urllib3, starlette, langsmith, requests, idna, uv, pytest, etc.). If a targeted in-range alert still remains after re-lock (an intermediary pins the transitive dep below its fix), resolve it with a `[tool.uv]` constraint/override or by bumping the intermediary — never leave it silently open (spec Edge Case "transitive-only fix unavailable").
- [ ] T009 [US1] Refresh the frontend lockfile: in `ui/`, run `npm update` then `npm audit fix` (NOT `--force`); commit `ui/package-lock.json`. Clears the in-range npm alerts (vite, react-router, postcss, picomatch, js-yaml, uuid, @babel/core).
- [~] T010 [US1] (Python gates green: 2232 pass, ruff/format/mypy clean, cov 82.26%; frontend build pending T009) Run the regression oracle and fix any drift from the bumps: `uv run ruff check . && uv run ruff format --check . && uv run mypy ziran/ && uv run pytest --cov=ziran` (≥85%) and `cd ui && npm run build`.
- [X] T011 [US1] Enable secret scanning + push protection via `gh api -X PATCH repos/taoq-ai/ziran` (`security_and_analysis.secret_scanning` + `secret_scanning_push_protection` = enabled). If the token lacks admin scope, document the exact Settings → Code security steps in the PR for the maintainer (per clarification Q1 / FR-005).

**Checkpoint**: ~90% of the backlog and all code-scanning alerts cleared; mergeable on its own.

---

## Phase 4: User Story 2 — Compatibility-sensitive major upgrades (Priority: P2)

**Goal**: Resolve the 7 out-of-range alerts (the langchain 0.x→1.x family) by widening caps + compat testing.

**Independent Test**: The 7 langchain-family alerts resolve and the langchain adapter + pentest orchestrator still pass their tests.

- [~] T012 [US2] (SUPERSEDED: langchain family is crewai-blocked, not cap-blocked; resolved as accept-risk-not-reachable in P3 + follow-up #332) Widen the langchain-family caps in `pyproject.toml` from `<1` to `<2` for `langchain`, `langchain-community`, `langchain-openai`, `langchain-core`, `langgraph`; then `uv lock` + `uv sync --frozen` and commit `pyproject.toml` + `uv.lock`.
- [~] T013 [US2] (N/A — no langchain upgrade performed; see #332) Verify langchain 1.x compatibility: run `uv run pytest -m "unit or integration" -k "langchain or pentest"` plus the full gate matrix (`mypy ziran/`, `pytest --cov=ziran`); fix any adapter breakage from langchain 1.0 package reorganization/deprecations (per research.md R9).

**Checkpoint**: zero open Dependabot alerts of any severity except the 2 no-fix items.

---

## Phase 5: User Story 3 — No-fix packages (Priority: P3)

**Goal**: Give chromadb (critical) and diskcache (medium) a recorded decision.

**Independent Test**: Each no-fix alert is no longer undecided — reachability assessed and a row added to the decision record + GitHub dismissal.

- [X] T014 [P] [US3] Trace chromadb's entry into the dependency tree (`uv tree | grep -i chromadb`), assess whether the vulnerable code path is reachable in ZIRAN's usage; mitigate/pin if reachable, else dismiss-with-reason in GitHub AND add the row to `docs/security/risk-acceptances.md` (Reachable? `unknown` ⇒ treat as reachable).
- [X] T015 [P] [US3] Same for diskcache: trace, assess reachability, decide, and record in both GitHub and `docs/security/risk-acceptances.md`.

**Checkpoint**: every open Dependabot alert is either fixed or recorded.

---

## Phase 6: User Story 4 — Prevention (Priority: P4)

**Goal**: Stop the backlog re-accumulating — scheduled grouped updates + a blocking CI audit gate covering both ecosystems.

**Independent Test**: The audit gate fails on an introduced high-severity dep and passes on the clean tree (incl. accepted dismissals); Dependabot validates the config with no error.

- [X] T016 [P] [US4] Create `.github/dependabot.yml` per `contracts/dependabot-config.md` — `version: 2`, three weekly **grouped** ecosystems: `pip` (`/`), `npm` (`/ui`), `github-actions` (`/`).
- [X] T017 [US4] Add a `dependency-audit` job to `.github/workflows/ci.yml` per `contracts/dependency-audit-gate.md`: `pip-audit` (high/critical fail) with `--ignore-vuln` for exactly the `accept-risk-no-fix` pip GHSA IDs from `docs/security/risk-acceptances.md`, plus `cd ui && npm audit --audit-level=high`. (Depends on T014/T015 for the GHSA suppression IDs.)
- [~] T018 (gate built; npm-audit step will correctly fail on the current ui lockfile until T009 runs — proving it bites; pip-audit validated in CI env, sandbox blocks local venv) [US4] Verify the gate bites: on a throwaway branch, pin a known high-severity dependency and confirm the `dependency-audit` job fails; confirm the clean tree passes; revert the throwaway change.

**Checkpoint**: backlog cannot silently rebuild.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [~] T019 (verified via API: 16 Dependabot dismissed, CodeQL 5→4 open [#7 dismissed], rest fixed-in-commit pending merge) Final acceptance (SC-001/SC-007): re-query `gh api repos/taoq-ai/ziran/dependabot/alerts?state=open` and `.../code-scanning/alerts?state=open` → zero open except recorded no-fix; confirm every still-open alert has a matching row in `docs/security/risk-acceptances.md`.
- [~] T020 (spec set Active; PR pending — held until v0.33.0 #328 cut) Set spec 024 Status to Active in `specs/024-security-alert-remediation/spec.md`; reference issue #330 in each slice PR; confirm every PR targets `develop` (gitflow).

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002)** → **User Stories** → **Polish**.
- **US1 (P1)** depends only on Foundational; it is the MVP and merges first (it also establishes the upgraded `uv.lock` baseline the later slices build on).
- **US2 (P2)** builds on US1's lockfile (re-locks after the cap change). Independent of US3/US4.
- **US3 (P3)** is independent of US2. Its decisions (T014/T015) produce the GHSA IDs that **US4's T017** consumes — so **T017 depends on T014/T015**.
- **US4 (P4)**: T016 is independent; T017 depends on US3; T018 depends on T017.
- Within a story, `[P]` tasks touch different files and may run concurrently.

### Story dependency graph

```text
Setup → Foundational ─┬─▶ US1 (MVP) ──▶ US2 (langchain 1.x)
                      │
                      ├─▶ US3 (no-fix) ──▶ US4:T017 (audit gate ignore-list)
                      └─▶ US4:T016 (dependabot.yml)
```

## Parallel Execution Examples

- **US1**: T003 ∥ T004 ∥ T005 ∥ T006 (distinct workflow/test files) can run together; T007 (dismissal) parallel to the lockfile work; T008 then T009 then T010 (gate) sequential at the end.
- **US3**: T014 ∥ T015 (different packages, different rows).
- **US4**: T016 ∥ (US3 tasks); T017 after US3; T018 after T017.

## Implementation Strategy

1. **MVP = Phases 1–3 (US1)**: clears ~90% of Dependabot + all CodeQL + secret scanning, no constraint changes — ship as the first PR.
2. **Increment 2 = US2**: the one real compatibility risk (langchain 1.x), isolated.
3. **Increment 3 = US3**: documented decisions for the 2 no-fix packages.
4. **Increment 4 = US4**: prevention guard rails.
5. **Polish**: final zero-backlog verification + spec status.

> **Sequencing note**: per the spec's dependency on #328, land these PRs after the v0.33.0 release cut to keep the release branch clean.
