# Implementation Plan: Web UI Foundation

**Branch**: `008-web-ui-foundation` | **Date**: 2026-03-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/008-web-ui-foundation/spec.md`

## Summary

Add a web dashboard to ziran via FastAPI backend (PostgreSQL + Alembic) and React frontend (Vite + TypeScript + shadcn/ui + Tailwind). The frontend source lives at `ui/` in the repo root, builds to `ziran/interfaces/web/static/`, and is bundled into the PyPI wheel. A new `ziran ui` CLI command launches the server. Covers GitHub issues #105, #86, #88, #92, #103.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + TypeScript 5.x (frontend)
**Primary Dependencies**: FastAPI, SQLAlchemy (async), asyncpg, Alembic, uvicorn (backend); React 18, Vite, TanStack Query, shadcn/ui, Tailwind CSS, vis-network (frontend)
**Storage**: PostgreSQL via asyncpg (configurable via `ZIRAN_DATABASE_URL` env var)
**Testing**: pytest + pytest-asyncio (backend), Vitest (frontend — future)
**Target Platform**: Linux/macOS/Windows (Python CLI + local web server)
**Project Type**: CLI tool extending to embedded web service
**Performance Goals**: Dashboard loads in <3s, DB migrations complete in <5s
**Constraints**: Zero Node.js at runtime; frontend bundled in Python wheel
**Scale/Scope**: Single-user local tool; 5 pages, 6 API routes, 3 DB tables, 1 WebSocket endpoint

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | PASS | Web backend lives in `interfaces/web/` (driving adapter). Uses `application/` factories and scanner. No domain changes needed. |
| II. Type Safety | PASS | All Python code uses type annotations + Pydantic models. SQLAlchemy models are typed. Frontend uses TypeScript strict mode. mypy strict must pass. |
| III. Test Coverage | PASS | Unit tests for models, schemas, app factory, CLI command. Integration tests for DB lifecycle and API health. Coverage >= 85%. |
| IV. Async-First | PASS | FastAPI is async-native. SQLAlchemy uses async engine (asyncpg). Alembic runs async migrations. |
| V. Extensibility via Adapters | PASS | Web interface is a new driving adapter — does not modify existing adapters or domain contracts. |
| VI. Simplicity | PASS | Minimal foundation: 3 tables, 1 health endpoint, SPA serving. No premature features. |
| Quality Gates | PASS | ruff, mypy, pytest all apply to new code. Frontend excluded from Python linting. |

**No violations. Gate passes.**

## Project Structure

### Documentation (this feature)

```text
specs/008-web-ui-foundation/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
ziran/
├── interfaces/
│   ├── cli/
│   │   └── main.py              # Add `ziran ui` command
│   └── web/                     # NEW — FastAPI driving adapter
│       ├── __init__.py
│       ├── app.py               # FastAPI app factory (create_app)
│       ├── config.py            # WebUIConfig Pydantic settings
│       ├── models.py            # SQLAlchemy ORM models
│       ├── schemas.py           # Pydantic request/response schemas
│       ├── dependencies.py      # FastAPI DI (get_db session)
│       ├── migrations/          # Alembic migrations directory
│       │   ├── env.py
│       │   ├── script.py.mako
│       │   └── versions/
│       │       └── 001_initial_schema.py
│       ├── routes/
│       │   ├── __init__.py
│       │   └── health.py        # GET /api/health
│       └── static/              # Built React assets (gitignored)

ui/                              # NEW — React/Vite source (NOT in wheel)
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── index.html
├── components.json              # shadcn/ui config
└── src/
    ├── main.tsx
    ├── App.tsx                  # React Router + TanStack Query setup
    ├── api/
    │   └── client.ts            # Base fetch wrapper
    ├── components/
    │   ├── layout/
    │   │   ├── Layout.tsx       # Sidebar + main content
    │   │   ├── Sidebar.tsx
    │   │   └── Header.tsx
    │   └── ui/                  # shadcn/ui primitives
    ├── pages/
    │   ├── Dashboard.tsx        # Empty state with stats placeholders
    │   ├── NewRun.tsx           # Placeholder
    │   ├── RunDetail.tsx        # Placeholder
    │   ├── Library.tsx          # Placeholder
    │   └── Settings.tsx         # Placeholder
    ├── hooks/
    │   └── useWebSocket.ts      # Placeholder for future WS
    ├── lib/
    │   └── utils.ts             # shadcn/ui cn() utility
    └── types/
        └── index.ts             # TS types mirroring Pydantic schemas

tests/
├── unit/
│   ├── test_web_config.py       # WebUIConfig defaults and env overrides
│   ├── test_web_models.py       # SQLAlchemy model creation
│   └── test_web_schemas.py      # Pydantic schema validation
└── integration/
    └── test_web_app.py          # App factory, health endpoint, SPA fallback

hatch_build.py                   # Custom hatch build hook for frontend
```

**Structure Decision**: Follows the existing hexagonal architecture. The web backend is a new driving adapter in `interfaces/web/`, parallel to `interfaces/cli/`. The frontend source is at `ui/` (repo root) to keep Node toolchain separate from Python. Built assets land in `ziran/interfaces/web/static/` for inclusion in the wheel.

## Complexity Tracking

No constitution violations to justify.
