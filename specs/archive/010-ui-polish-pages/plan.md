# Implementation Plan: UI Batch 3 — Pages, Polish & Docker

**Branch**: `010-ui-polish-pages` | **Date**: 2026-03-30 | **Spec**: [spec.md](spec.md)

## Summary

Complete the remaining UI pages (knowledge graph, attack library, settings), add Docker support, and polish UX (skeletons, error boundaries, empty states, responsive layout). All work targets single-developer community edition.

## Technical Context

**Language/Version**: Python 3.11+ (backend), TypeScript 5.x (frontend)
**Primary Dependencies**: FastAPI, SQLAlchemy 2.0 (async), Pydantic v2 (backend); React 18, Vite, TanStack Query/Table, shadcn/ui, Tailwind CSS, vis-network (frontend)
**Storage**: PostgreSQL via asyncpg (existing `ZIRAN_DATABASE_URL`)
**Testing**: pytest + httpx (backend)
**Project Type**: Web application (Python package with bundled frontend)

## Constitution Check

| Gate | Status | Notes |
|------|--------|-------|
| I. Hexagonal Architecture | PASS | Library API reads from application layer (AttackLibrary). Graph data from existing domain export. |
| II. Type Safety | PASS | All new routes typed, Pydantic schemas for all endpoints. |
| III. Test Coverage | PASS | Unit tests for new routes, integration tests for presets CRUD. |
| IV. Async-First | PASS | All new endpoints async. |
| V. Extensibility | PASS | No new adapters needed. Library API reads existing YAML vectors. |
| VI. Simplicity | PASS | No new abstractions — direct SQLAlchemy for presets, direct AttackLibrary for vectors. |

## Project Structure

### Source Code (new/modified files)

```text
ziran/interfaces/web/
├── routes/
│   ├── library.py               # NEW: /api/library/* endpoints
│   └── configs.py               # NEW: /api/configs/* CRUD endpoints
├── schemas.py                   # MODIFY: add Library, Config schemas
├── app.py                       # MODIFY: register new routers

ui/src/
├── components/
│   ├── graph/
│   │   └── KnowledgeGraph.tsx   # NEW: vis-network graph component
│   ├── library/
│   │   ├── VectorTable.tsx      # NEW: filterable vector table
│   │   └── VectorDetail.tsx     # NEW: expandable vector detail
│   ├── ui/
│   │   ├── Skeleton.tsx         # NEW: skeleton loader
│   │   └── ErrorBoundary.tsx    # NEW: error boundary with retry
│   └── layout/
│       └── Sidebar.tsx          # MODIFY: responsive hamburger
├── pages/
│   ├── Library.tsx              # REWRITE: from placeholder
│   ├── Settings.tsx             # REWRITE: from placeholder
│   ├── RunDetail.tsx            # MODIFY: add KnowledgeGraph component
│   └── NotFound.tsx             # NEW: 404 page
├── api/
│   ├── library.ts               # NEW: library API hooks
│   └── configs.ts               # NEW: config presets hooks
└── types/index.ts               # MODIFY: add Library, Config types

Dockerfile                       # NEW
docker-compose.yml               # NEW
.env.example                     # NEW
.dockerignore                    # NEW
```

## Key Technical Decisions

### 1. Knowledge Graph — vis-network

Use `vis-network` (same as HTML report) via `vis-data` and `vis-network/standalone`. Port node color/shape/size constants from `html_report.py` to TypeScript. Graph receives `graph_state_json` from the existing Run detail API — no new backend endpoint needed.

For large graphs (>200 nodes): disable physics on initial render, use `stabilize()` before display.

### 2. Attack Library — Read-Only API

The library API is read-only — it instantiates `AttackLibrary` and returns vector metadata. No database involved. Vectors are loaded from bundled YAML files in `ziran/application/attacks/vectors/`. The API exposes filtering (category, severity, phase, owasp, text search) and stats aggregation.

### 3. Config Presets — Existing Model

The `ConfigPreset` model already exists in `models.py` with id, name, description, config_json, created_at, updated_at. Just need CRUD routes and frontend.

### 4. Docker — Multi-Stage Build

- Stage 1 (Node): Build frontend → `static/`
- Stage 2 (Python): Install `ziran[ui]`, copy built static, expose 8484
- docker-compose.yml: `ziran-ui` + `postgres` services with persistent volume

### 5. UX Polish

- Skeleton: shadcn/ui `<Skeleton>` component for tables/cards
- Error boundary: React error boundary wrapping pages, with retry button
- Empty states: Per-page components with icon + message + CTA
- Responsive: Tailwind `md:` breakpoint, sidebar collapses below 768px
- 404: Simple page with link back to Dashboard
