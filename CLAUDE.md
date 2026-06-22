# ziran Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-06-22

## Active Technologies
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + asyncio, dataclasses, logging, OpenTelemetry (tracing) (003-split-agent-scanner)
- N/A (in-memory knowledge graph via NetworkX) (003-split-agent-scanner)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + Pydantic (config models), re (stdlib regex) (003-precompile-regex-patterns)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + PyYAML (scenario loading), Pydantic (schema validation) (007-ground-truth-business-impact)
- YAML files (ground truth scenarios and agent archetypes) (007-ground-truth-business-impact)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + TypeScript 5.x (frontend) + FastAPI, SQLAlchemy (async), asyncpg, Alembic, uvicorn (backend); React 18, Vite, TanStack Query, shadcn/ui, Tailwind CSS, vis-network (frontend) (008-web-ui-foundation)
- PostgreSQL via asyncpg (configurable via `ZIRAN_DATABASE_URL` env var) (008-web-ui-foundation)
- Python 3.11+ (backend), TypeScript 5.x (frontend) + FastAPI, SQLAlchemy 2.0 (async), Alembic, Pydantic v2 (backend); React 18, Vite, TanStack Query, TanStack Table, shadcn/ui, Tailwind CSS (frontend) (009-ui-findings-compliance)
- PostgreSQL via asyncpg (existing `ZIRAN_DATABASE_URL`) (009-ui-findings-compliance)
- Python 3.11+ (backend), TypeScript 5.x (frontend) + FastAPI, SQLAlchemy 2.0 (async), Pydantic v2 (backend); React 18, Vite, TanStack Query/Table, shadcn/ui, Tailwind CSS, vis-network (frontend) (010-ui-polish-pages)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + click (CLI), httpx (async HTTP), pydantic (models), networkx (graph), pyyaml (config), rich (output), mdutils (reports). New optional: `langfuse` (trace pull). (011-runtime-bridge-v0-8)
- Local JSON files for registry snapshots (`.ziran/snapshots/`); no database. (011-runtime-bridge-v0-8)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + pydantic (models), PyYAML (vector loader), click (CLI), rich (reports), networkx (graph — unchanged). No new dependencies. (012-benchmark-maturity)
- YAML vector files under `ziran/application/attacks/vectors/`; benchmark result JSON under `benchmarks/results/`; docs under `docs/reference/benchmarks/`. (012-benchmark-maturity)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + `re` (stdlib), existing `ziran.application.detectors` module (013-multilingual-refusal-detection)
- N/A (in-memory pattern matching) (013-multilingual-refusal-detection)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + httpx (async HTTP — Slack + GitHub REST), Pydantic v2 (config + entity models), PyYAML (config + new `!env` tag), Click (CLI). Composite GitHub Action uses `gh` CLI + bash, no new runtime deps. (017-runtime-loop-alerting)
- None new. Dedup is stateless via GitHub-side issue markers; existing registry snapshots stay in `.ziran/snapshots/` (local JSON). (017-runtime-loop-alerting)
- Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2 (threshold + dataset models), PyYAML (dataset + config loading, reusing `load_yaml_with_env`), Click (benchmark CLI entry point), existing `ziran.application.detectors` pipeline. No new runtime dependencies. (021-detection-accuracy-benchmark)
- YAML files for the labelled dataset (under `benchmarks/ground_truth/detection/`) and for operator config (`.ziran/detectors.yaml`); JSON result + baseline artifacts under `benchmarks/results/` (existing pattern). (021-detection-accuracy-benchmark)
- Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2 (cassette + comparison + result models), PyYAML (CVE target definitions, reusing spec-007 schema), Click/argparse (benchmark CLI), existing `AgentScanner` + `PentestOrchestrator`. Recording (opt-in) additionally needs the existing `pentest` extra (langgraph) + a live `BaseLLMClient`. No new runtime dependencies. (022-pentest-vs-scanner-benchmark)
- YAML for CVE-modeled ground-truth agents (`benchmarks/ground_truth/agents/`); JSON cassettes for recorded agent runs (`benchmarks/ground_truth/pentest_runs/`); JSON results + baseline under `benchmarks/results/` (existing pattern). (022-pentest-vs-scanner-benchmark)
- Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2 (`ManyShotConfig` model + validators), PyYAML (vectors + synthetic corpus loading), existing `AttackLibrary` / `AttackExecutor` / `AgentScanner`. No new runtime dependencies (token estimate is a char heuristic, not `tiktoken`). (023-many-shot-jailbreak)
- YAML — the vector file (`ziran/application/attacks/vectors/many_shot_jailbreak.yaml`) and a synthetic shot corpus (`ziran/application/attacks/vectors/many_shot_corpus.yaml`). (023-many-shot-jailbreak)
- Python 3.11+ (CI matrix 3.11/3.12/3.13) backend; TypeScript 5.x / Node frontend — *no new source code*, only manifests, lockfiles, CI workflows, and docs. + package managers + audit tooling — `uv` (Python lock/sync), `npm` (frontend lock), `pip-audit` (Python vuln gate), `npm audit` (frontend vuln gate). No new runtime dependencies in `ziran/`. (024-security-alert-remediation)
- N/A (no data store). The committed risk-acceptance record (`docs/security/risk-acceptances.md`) is the only new persisted artifact. (024-security-alert-remediation)

- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + click (CLI only), PyYAML, Playwright (optional), boto3 (optional), LangChain (optional), CrewAI (optional) (002-extract-shared-factories)

## Project Structure

```text
src/
tests/
```

## Commands

cd src [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] pytest [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] ruff check .

## Code Style

Python 3.11+ (CI matrix: 3.11, 3.12, 3.13): Follow standard conventions

## Recent Changes
- 024-security-alert-remediation: Added Python 3.11+ (CI matrix 3.11/3.12/3.13) backend; TypeScript 5.x / Node frontend — *no new source code*, only manifests, lockfiles, CI workflows, and docs. + package managers + audit tooling — `uv` (Python lock/sync), `npm` (frontend lock), `pip-audit` (Python vuln gate), `npm audit` (frontend vuln gate). No new runtime dependencies in `ziran/`.
- 023-many-shot-jailbreak: Added Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2 (`ManyShotConfig` model + validators), PyYAML (vectors + synthetic corpus loading), existing `AttackLibrary` / `AttackExecutor` / `AgentScanner`. No new runtime dependencies (token estimate is a char heuristic, not `tiktoken`).
- 022-pentest-vs-scanner-benchmark: Added Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2 (cassette + comparison + result models), PyYAML (CVE target definitions, reusing spec-007 schema), Click/argparse (benchmark CLI), existing `AgentScanner` + `PentestOrchestrator`. Recording (opt-in) additionally needs the existing `pentest` extra (langgraph) + a live `BaseLLMClient`. No new runtime dependencies.


<!-- MANUAL ADDITIONS START -->

## Speckit Workflow (MANDATORY)

All non-trivial features, refactors, and bug fixes MUST follow spec-driven development using speckit. Trivial changes (typo fixes, single-line config changes, comment updates) are exempt.

### Required workflow order

1. `/speckit.specify` — Create feature spec (what and why)
2. `/speckit.clarify` — Resolve ambiguities (if needed)
3. `/speckit.plan` — Design implementation (how)
4. `/speckit.tasks` — Generate ordered work breakdown
5. `/speckit.implement` — Execute tasks phase by phase

### Additional commands

- `/speckit.analyze` — Cross-artifact consistency analysis (spec ↔ plan ↔ tasks)
- `/speckit.checklist` — Generate quality checklists for requirements
- `/speckit.constitution` — View or amend the project constitution
- `/speckit.taskstoissues` — Convert tasks to GitHub issues

### Constitution

Read `.specify/memory/constitution.md` before starting any work. It defines architecture, type safety, test coverage, and quality gate requirements.

### Spec directory structure

- Active specs: `specs/NNN-feature-name/` (containing spec.md, plan.md, tasks.md)
- Archived specs: `specs/archive/NNN-feature-name/`
- Statuses: Draft → Active → Accepted → Superseded → Deprecated
- Specs are never deleted; archive when superseded or deprecated

### Quality gates (must pass before any PR)

```bash
uv run ruff check .              # Lint — zero violations
uv run ruff format --check .     # Format — zero drift
uv run mypy ziran/               # Type check — zero errors (strict)
uv run pytest --cov=ziran        # Tests — all pass, coverage >= 85%
```

### Branching (gitflow)

- This repo follows **gitflow**: `develop` is the integration branch, `main` is release-only.
- Branch feature/fix work off `develop`, and **open pull requests against `develop`** (NOT `main`). `main` only receives merges via release branches.
- CI workflows trigger on both `main` and `develop`.

### Commit rules

- **NEVER** add `Co-Authored-By` trailers to commits. Use only the default git author config.
- Conventional Commits format: `type: description` (e.g., `feat(ui): add findings page`)

### CI pipeline (MANDATORY)

- After every `git push`, ALWAYS check the CI pipeline status (`gh pr checks`) and wait for results.
- If any check fails, investigate and fix before proceeding to next work.
- Do NOT leave a PR with failing CI — fix it immediately.

<!-- MANUAL ADDITIONS END -->
