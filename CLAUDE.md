# ziran Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-03-24

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
- 009-ui-findings-compliance: Added Python 3.11+ (backend), TypeScript 5.x (frontend) + FastAPI, SQLAlchemy 2.0 (async), Alembic, Pydantic v2 (backend); React 18, Vite, TanStack Query, TanStack Table, shadcn/ui, Tailwind CSS (frontend)
- 008-web-ui-foundation: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + TypeScript 5.x (frontend) + FastAPI, SQLAlchemy (async), asyncpg, Alembic, uvicorn (backend); React 18, Vite, TanStack Query, shadcn/ui, Tailwind CSS, vis-network (frontend)
- 007-ground-truth-business-impact: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + PyYAML (scenario loading), Pydantic (schema validation)


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

### Commit rules

- **NEVER** add `Co-Authored-By` trailers to commits. Use only the default git author config.
- Conventional Commits format: `type: description` (e.g., `feat(ui): add findings page`)

### CI pipeline (MANDATORY)

- After every `git push`, ALWAYS check the CI pipeline status (`gh pr checks`) and wait for results.
- If any check fails, investigate and fix before proceeding to next work.
- Do NOT leave a PR with failing CI — fix it immediately.

<!-- MANUAL ADDITIONS END -->
