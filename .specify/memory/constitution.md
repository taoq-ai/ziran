<!--
  Sync Impact Report
  Version change: 1.0.0 → 1.1.0 (clarify hexagonal architecture)
  Modified principles: Clean Architecture → Hexagonal Architecture (clarified port/adapter terminology)
  Added sections: Quality Gates, Specification Lifecycle
  Templates requiring updates:
    - .specify/templates/plan-template.md ✅ (Constitution Check section already present)
    - .specify/templates/spec-template.md ✅ (no changes needed)
    - .specify/templates/tasks-template.md ✅ (no changes needed)
  Follow-up TODOs: none
-->

# Ziran Constitution

## Core Principles

### I. Hexagonal Architecture (Ports & Adapters)

All code MUST follow hexagonal architecture (ports and adapters):

- **domain/** — Entities and ports (interfaces). Zero external dependencies. Defines the contracts (ports) that the outside world must implement.
- **application/** — Use cases and business logic. Depends only on domain. Orchestrates domain entities through ports.
- **infrastructure/** — Adapters that implement domain ports (e.g., `BaseAgentAdapter` implementations, HTTP clients, storage backends, LLM providers).
- **interfaces/** — Driving adapters (CLI, REST API) that invoke application use cases.

Dependencies MUST flow inward: interfaces → application → domain ← infrastructure. The domain MUST NOT depend on any outer layer. Infrastructure implements domain ports but is never imported by domain or application directly.

### II. Type Safety (NON-NEGOTIABLE)

- All function parameters and return types MUST have type annotations
- Pydantic models MUST be used for all data structures (no plain dicts for domain data)
- mypy strict mode MUST pass with zero errors
- ABC interfaces MUST define contracts for all extensibility points

### III. Test Coverage

- Unit tests MUST exist for all business logic (application layer)
- Integration tests MUST exist for adapter contracts and cross-layer interactions
- Coverage MUST remain at or above 85% on `main`
- Tests MUST use pytest markers (`@pytest.mark.unit`, `@pytest.mark.integration`)
- MockAgentAdapter MUST be used for unit tests; real adapters only in integration tests

### IV. Async-First

- All I/O operations (HTTP, agent interactions, file reads) MUST use async/await
- httpx MUST be used for HTTP clients (not requests)
- Sync wrappers are acceptable only at CLI entry points

### V. Extensibility via Adapters

- New agent frameworks MUST be supported by implementing `BaseAgentAdapter`
- New attack vectors MUST be added as YAML definitions, not code changes
- New detectors MUST implement the `Detector` interface
- The knowledge graph (NetworkX MultiDiGraph) is the single source of truth during campaigns

### VI. Simplicity

- Prefer composition over inheritance
- No premature abstractions — three similar lines are better than a helper used once
- YAGNI: do not build for hypothetical future requirements
- Every added dependency MUST be justified

## Quality Gates

All code changes MUST pass before merge:

1. **Lint**: `ruff check .` — zero violations
2. **Format**: `ruff format --check .` — zero drift
3. **Types**: `mypy ziran/` — zero errors (strict mode)
4. **Tests**: `pytest --cov=ziran` — all pass, coverage >= 85%
5. **CI matrix**: Python 3.11, 3.12, 3.13

Line length limit is 100 characters. Import sorting follows isort conventions (first-party: `ziran`).

## Specification Lifecycle

All non-trivial features MUST go through spec-driven development using speckit:

1. `/speckit.specify` → spec.md (what and why)
2. `/speckit.plan` → plan.md (how)
3. `/speckit.tasks` → tasks.md (work breakdown)
4. `/speckit.implement` → execution

Spec statuses: **Draft → Active → Accepted → Superseded → Deprecated**

- Active specs live in `specs/NNN-name/`
- Superseded or deprecated specs MUST be moved to `specs/archive/NNN-name/`
- Specs are never deleted; git history is the permanent archive

## Governance

- This constitution supersedes ad-hoc practices. All PRs MUST comply.
- Amendments require updating this file, incrementing the version, and documenting changes in the Sync Impact Report comment at the top.
- Versioning: MAJOR for principle removals/redefinitions, MINOR for additions, PATCH for clarifications.
- Conventional Commits MUST be used for all commit messages (`type: description`).
- Branch names MUST follow `type/NNN-short-name` format (e.g., `ci/001-release-please-automation`).

**Version**: 1.1.0 | **Ratified**: 2026-03-20 | **Last Amended**: 2026-03-20
