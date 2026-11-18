# Research: Web UI Foundation

## R1: Hatch Build Hook for Frontend Bundling

**Decision**: Custom hatch build hook (`hatch_build.py`) that runs `npm ci && npm run build` before wheel packaging.

**Rationale**: Hatchling supports custom build hooks via `[tool.hatch.build.hooks.custom]`. This integrates frontend compilation into the standard `uv build` / `hatch build` workflow. The hook checks for Node.js availability and skips gracefully if absent, ensuring core CLI users aren't blocked.

**Alternatives considered**:
- CI-only build (simpler but breaks local `pip install -e ".[ui]"` for developers)
- Makefile/script wrapper (not integrated with Python build toolchain)
- Pre-built static checked into git (bloats repo, stale assets)

## R2: Alembic Async Migrations with PostgreSQL

**Decision**: Use Alembic with async engine (`asyncpg`) and run migrations on server startup via `alembic.command.upgrade("head")`.

**Rationale**: Alembic is the standard SQLAlchemy migration tool. It supports async engines since 1.12+ via `run_async()` in `env.py`. Running migrations on startup ensures schema is always current without manual steps.

**Implementation notes**:
- `alembic.ini` is NOT needed — configure programmatically via `alembic.config.Config` in `app.py`
- Migration directory: `ziran/interfaces/web/migrations/`
- Initial migration creates `runs`, `phase_results`, `config_presets` tables
- `env.py` uses `connectable = create_async_engine(url)` with `run_async()`

**Alternatives considered**:
- Raw `metadata.create_all()` (no versioned migrations, breaks upgrades)
- Manual migration CLI command (user burden, forgettable)

## R3: FastAPI SPA Fallback

**Decision**: Mount `StaticFiles` at root for assets, plus a catch-all route that returns `index.html` for client-side routing.

**Rationale**: React Router uses client-side routes (e.g., `/runs/123`). Without SPA fallback, direct navigation or refresh returns 404. The pattern: API routes under `/api/`, static assets served by Starlette's `StaticFiles`, and a catch-all HTML response for everything else.

**Implementation**:
```python
# In create_app():
# 1. Mount API router at /api
# 2. Mount StaticFiles for /assets (JS/CSS chunks)
# 3. Catch-all route returns index.html
```

**Alternatives considered**:
- Nginx/reverse proxy (adds deployment complexity for a local tool)
- Hash-based routing (worse UX, breaks deep linking)

## R4: Vite Build Output Configuration

**Decision**: Vite `build.outDir` set to `../ziran/interfaces/web/static/` (relative to `ui/`). Vite dev server proxies `/api/*` and `/ws/*` to `http://localhost:8484`.

**Rationale**: Build output lands directly where FastAPI's `StaticFiles` serves from. Dev proxy avoids CORS issues entirely — frontend and backend appear same-origin during development.

**Vite config key settings**:
```typescript
export default defineConfig({
  build: { outDir: '../ziran/interfaces/web/static/' },
  server: {
    proxy: {
      '/api': 'http://localhost:8484',
      '/ws': { target: 'ws://localhost:8484', ws: true }
    }
  }
})
```

## R5: Optional Dependency Guard Pattern

**Decision**: The `ziran ui` CLI command uses `try/except ImportError` to detect missing `[ui]` dependencies and prints a helpful message.

**Rationale**: Follows the same pattern used by existing optional extras (langchain, crewai, browser). Users who install `pip install ziran` (no extras) get a clear error pointing them to `pip install ziran[ui]`.

**Pattern** (from existing codebase):
```python
@cli.command()
def ui(host, port, dev):
    try:
        import uvicorn
        from ziran.interfaces.web.app import create_app
    except ImportError:
        console.print("[red]Web UI dependencies not installed.[/red]")
        console.print("Run: pip install ziran[ui]")
        raise SystemExit(1)
```

## R6: SQLAlchemy Async Model Patterns

**Decision**: Use SQLAlchemy 2.0 declarative base with `mapped_column()`, async session via `async_sessionmaker`, and JSONB columns for complex nested data.

**Rationale**: SQLAlchemy 2.0 style is type-safe with mypy plugin support. JSONB columns for `result_json`, `graph_state_json`, `config_json` avoid excessive table normalization for data that's read as a whole.

**Key decisions**:
- UUID primary keys (matches existing `campaign_id` format)
- `status` as String enum (pending/running/completed/failed/cancelled)
- `result_json` stores full serialized `CampaignResult` for the detail view
- `graph_state_json` stores graph export for vis-network rendering
- Timestamps use `DateTime(timezone=True)` with server defaults

## R7: Frontend Tech Stack Validation

**Decision**: React 18 + TypeScript + Vite + TanStack Router + TanStack Query + Tailwind CSS + shadcn/ui + lucide-react

**Rationale**: Matches the stack defined in GitHub issues (#92) and the qkd-playground reference project. TanStack Query handles server state with caching and refetching. shadcn/ui provides accessible, copy-paste components that don't add heavy dependencies.

**Key packages**:
- `react`, `react-dom` (18.x)
- `react-router-dom` (v6)
- `@tanstack/react-query` (v5)
- `tailwindcss` (v3)
- `lucide-react` (icons)
- `vis-network` (graph visualization — future use)
- `clsx`, `tailwind-merge` (for shadcn/ui `cn()` utility)

## R8: TaoQ Branding System

**Decision**: Dark mode default, teal accent (#4fd1c5), DM Sans font family.

**Rationale**: Defined in GitHub issue #176. Dark mode suits security tooling (reduces eye strain during long analysis sessions). Teal accent provides clear visual distinction from generic dashboards.

**Tailwind config**:
```typescript
theme: {
  extend: {
    colors: {
      accent: { DEFAULT: '#4fd1c5', ... }
    },
    fontFamily: {
      sans: ['DM Sans', 'system-ui', 'sans-serif']
    }
  }
}
```
