# Implementation Plan: UI Batch 2 — Findings Management, Compliance & Design System

**Branch**: `009-ui-findings-compliance` | **Date**: 2026-03-24 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/009-ui-findings-compliance/spec.md`

## Summary

Add findings management (extraction, API, UI), OWASP LLM Top 10 compliance matrix, community export endpoints, and TaoQ design system to the existing web UI foundation. Findings are denormalized from `result_json` (which contains serialized `CampaignResult` with `attack_results[]`) into a queryable `findings` table with deduplication via fingerprint hash. The frontend gets a Findings page with sortable/filterable table, detail drawer, OWASP matrix component, and full TaoQ branding.

## Technical Context

**Language/Version**: Python 3.11+ (backend), TypeScript 5.x (frontend)
**Primary Dependencies**: FastAPI, SQLAlchemy 2.0 (async), Alembic, Pydantic v2 (backend); React 18, Vite, TanStack Query, TanStack Table, shadcn/ui, Tailwind CSS (frontend)
**Storage**: PostgreSQL via asyncpg (existing `ZIRAN_DATABASE_URL`)
**Testing**: pytest + httpx (backend), Vitest (frontend — optional, not gated)
**Target Platform**: Linux/macOS server, modern browsers
**Project Type**: Web application (Python package with bundled frontend)
**Performance Goals**: Findings page < 1s for 10k findings, bulk updates < 2s for 100 items
**Constraints**: No npm publish (bundled in PyPI wheel), no auth (community single-user), synchronous exports
**Scale/Scope**: Single-user community tier, up to 10k findings across runs

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| I. Hexagonal Architecture | ✅ PASS | Findings extraction logic goes in `application/` as a use case. Web routes stay in `interfaces/web/routes/`. New DB models in `interfaces/web/models.py` (adapter layer). |
| II. Type Safety | ✅ PASS | All new models use Pydantic. All functions typed. mypy strict. |
| III. Test Coverage | ✅ PASS | Unit tests for extraction logic, integration tests for API endpoints. Coverage >= 85%. |
| IV. Async-First | ✅ PASS | All new endpoints async. DB queries via AsyncSession. |
| V. Extensibility via Adapters | ✅ PASS | OWASP mapping uses existing `OwaspLlmCategory` enum from domain. No new adapters needed. |
| VI. Simplicity | ✅ PASS | No premature abstractions. Direct SQLAlchemy queries, no repository pattern. |
| Quality Gates | ✅ PASS | ruff, mypy, pytest gates maintained. |

## Project Structure

### Documentation (this feature)

```text
specs/009-ui-findings-compliance/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── api.md           # Findings, compliance, export API contracts
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
ziran/interfaces/web/
├── models.py                    # ADD: Finding, ComplianceMapping, ExportJob models
├── schemas.py                   # ADD: Finding*, Compliance*, Export* schemas
├── routes/
│   ├── findings.py              # NEW: /api/findings/* endpoints
│   ├── compliance.py            # NEW: /api/compliance/* endpoints
│   └── export.py                # NEW: /api/export/* endpoints
├── services/
│   ├── run_manager.py           # MODIFY: call findings extraction after scan
│   └── findings_extractor.py    # NEW: extract AttackResult[] → Finding rows
└── migrations/versions/
    └── 002_findings_schema.py   # NEW: Alembic migration

ui/src/
├── components/
│   ├── ui/                      # MODIFY: shadcn components with TaoQ tokens
│   ├── layout/
│   │   ├── Sidebar.tsx          # MODIFY: add Findings nav link, TaoQ logo
│   │   └── ThemeToggle.tsx      # NEW: dark/light mode toggle
│   ├── findings/
│   │   ├── FindingsTable.tsx    # NEW: sortable/filterable table
│   │   ├── FindingDetail.tsx    # NEW: detail drawer/modal
│   │   ├── FindingFilters.tsx   # NEW: filter bar
│   │   ├── BulkActions.tsx      # NEW: bulk status change
│   │   └── SeverityBadge.tsx    # NEW: semantic color badges
│   └── compliance/
│       └── OwaspMatrix.tsx      # NEW: 10-cell OWASP grid
├── pages/
│   ├── Findings.tsx             # NEW: findings management page
│   └── Compliance.tsx           # NEW: compliance dashboard page
├── api/
│   ├── findings.ts              # NEW: findings API hooks
│   ├── compliance.ts            # NEW: compliance API hooks
│   └── export.ts                # NEW: export download functions
├── types/
│   └── index.ts                 # MODIFY: add Finding, Compliance types
└── styles/
    └── theme.ts                 # NEW: TaoQ design tokens as Tailwind config

tests/
├── unit/
│   ├── test_findings_extractor.py  # NEW
│   ├── test_findings_schemas.py    # NEW
│   └── test_web_models.py          # MODIFY: add Finding model tests
└── integration/
    ├── test_findings_api.py        # NEW
    ├── test_compliance_api.py      # NEW
    └── test_export_api.py          # NEW
```

**Structure Decision**: Extends existing web application layout (Python backend in `ziran/interfaces/web/`, React frontend in `ui/`). No new top-level directories. New route modules follow existing pattern (`routes/findings.py` alongside `routes/runs.py`). Findings extraction service follows hexagonal architecture — business logic in `services/findings_extractor.py`, invoked by `run_manager.py` after scan completion.

## Key Technical Decisions

### 1. Findings Extraction Strategy

The `result_json` JSONB column stores a serialized `CampaignResult` containing `attack_results[]` — each an `AttackResult` with `vector_id`, `severity`, `category`, `owasp_mapping[]`, `business_impact[]`, `agent_response`, `prompt_used`, etc.

**Approach**: After `RunManager` persists a completed scan, call `FindingsExtractor.extract(run)` which:
1. Deserializes `result_json` → `CampaignResult`
2. Iterates `attack_results` where `successful == True`
3. For each, computes `fingerprint = sha256(target + vector_id + category + severity)`
4. Upserts into `findings` table (deduplicate by fingerprint)
5. Creates `compliance_mappings` rows from `owasp_mapping[]`

### 2. Fingerprint Deduplication

Use `sha256(target_agent + vector_id + category)` — deterministic, collision-resistant. When a duplicate fingerprint is found across runs, the existing finding is updated with the latest run_id but status is preserved (user may have marked it as fixed/ignored).

### 3. OWASP Compliance Data

Leverage existing `OwaspLlmCategory` enum (10 categories, LLM01–LLM10) and `OWASP_LLM_DESCRIPTIONS` dict from `ziran/domain/entities/attack.py`. The compliance API aggregates finding counts grouped by `owasp_category` and returns coverage status per category.

### 4. TaoQ Design System

Apply design tokens from qkd-playground:
- **Colors**: Teal accent `#4fd1c5`, dark bg `#0a0a0a`, borders `#27272a`
- **Severity colors**: Critical=`#f87171`, High=`#fb923c`, Medium=`#fbbf24`, Low=`#4fd1c5`, Info=`#71717a`
- **Font**: DM Sans via Google Fonts CDN
- **Dark mode default**: `class` strategy in Tailwind, `dark` class on `<html>`
- Configure in `tailwind.config.ts` `extend.colors` and `extend.fontFamily`

### 5. Export Implementation

Synchronous streaming responses for community tier:
- **CSV**: `StreamingResponse` with `text/csv` content-type, `csv.writer` output
- **JSON**: Standard JSON response with `Content-Disposition: attachment` header
- **YAML**: `yaml.dump()` of run config, served as `application/x-yaml`
- **Markdown**: Template-based report generation, served as `text/markdown`

### 6. TanStack Table for Findings

Use `@tanstack/react-table` for the findings table — it provides:
- Column sorting (client-side for current page, server-side via API `sort` param)
- Row selection for bulk actions
- Column visibility toggle
- Integrates naturally with shadcn/ui `<Table>` components

## Complexity Tracking

No constitution violations. All design decisions use existing patterns.
