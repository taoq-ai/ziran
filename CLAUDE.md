# ziran Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-03-22

## Active Technologies
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + asyncio, dataclasses, logging, OpenTelemetry (tracing) (003-split-agent-scanner)
- N/A (in-memory knowledge graph via NetworkX) (003-split-agent-scanner)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + Pydantic (config models), re (stdlib regex) (003-precompile-regex-patterns)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + PyYAML (scenario loading), Pydantic (schema validation) (007-ground-truth-business-impact)
- YAML files (ground truth scenarios and agent archetypes) (007-ground-truth-business-impact)

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
- 007-ground-truth-business-impact: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + PyYAML (scenario loading), Pydantic (schema validation)
- 003-precompile-regex-patterns: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + Pydantic (config models), re (stdlib regex)
- 003-split-agent-scanner: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + asyncio, dataclasses, logging, OpenTelemetry (tracing)


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

<!-- MANUAL ADDITIONS END -->
