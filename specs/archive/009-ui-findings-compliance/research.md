# Research: UI Batch 2 — Findings Management, Compliance & Design System

**Date**: 2026-03-24

## R1: Findings Extraction from CampaignResult

**Decision**: Extract findings from `result_json.attack_results[]` after scan completion, filtering to `successful == True` entries only.

**Rationale**: The `CampaignResult.attack_results` list contains all `AttackResult` objects with full detail (severity, category, owasp_mapping, prompt_used, agent_response, evidence). This is the most complete source of individual vulnerability data. Filtering to successful attacks prevents noise from failed/benign test attempts.

**Alternatives considered**:
- Extract from `phase_results[].vulnerabilities_found` — rejected: only stores vulnerability IDs, not full detail.
- Query `result_json` via PostgreSQL JSONB operators — rejected: complex queries, no indexing on nested fields, slower than denormalized table.

## R2: Fingerprint Deduplication Strategy

**Decision**: `sha256(target_agent + vector_id + category)` — excludes severity and response pattern from fingerprint.

**Rationale**: Same vulnerability (same attack vector against same target in same category) should deduplicate even if severity is assessed differently across runs. Including severity would create false "new" findings when scoring changes.

**Alternatives considered**:
- Include `agent_response` hash — rejected: responses vary between runs for same vulnerability.
- Include `severity` — rejected: severity re-assessment should update existing finding, not create duplicate.
- Use `vector_name` instead of `vector_id` — rejected: names can change, IDs are stable identifiers.

## R3: TanStack Table vs Custom Table

**Decision**: Use `@tanstack/react-table` v8 for the findings data grid.

**Rationale**: Provides headless sorting, filtering, pagination, and row selection out of the box. Works with shadcn/ui `<Table>` components. No additional bundle size for UI — it's headless. Already a peer of TanStack Query in the project.

**Alternatives considered**:
- AG Grid — rejected: heavy bundle, overkill for our use case, license concerns.
- Custom table with useState — rejected: reimplementing sorting/selection/pagination is error-prone.

## R4: Export Format Implementation

**Decision**: Synchronous `StreamingResponse` for CSV/JSON, direct response for YAML/Markdown.

**Rationale**: Community tier is single-user, so no need for background job queue. Streaming keeps memory bounded for large CSV exports. For YAML/Markdown (small payloads), direct response is simpler.

**Alternatives considered**:
- Background job with polling — rejected: YAGNI for community tier. `export_jobs` table is schema-ready for future async support.
- Server-Sent Events for progress — rejected: unnecessary complexity for synchronous exports.

## R5: OWASP Compliance Matrix Data Source

**Decision**: Aggregate findings by `compliance_mappings.control_id` via a single SQL query with `GROUP BY`.

**Rationale**: The compliance API endpoint joins `findings` → `compliance_mappings`, groups by `control_id`, and returns counts per OWASP category. This is a simple aggregate query that PostgreSQL handles efficiently. The 10-category enum is already defined in `OwaspLlmCategory`.

**Alternatives considered**:
- Compute from `result_json` on-the-fly — rejected: slow for multiple runs, not queryable.
- Materialized view — rejected: premature optimization for community scale.

## R6: Dark Mode Implementation

**Decision**: Tailwind `darkMode: "class"` strategy with `dark` class on `<html>` element. Persist preference in `localStorage`.

**Rationale**: Class-based dark mode gives full control over theme switching without OS-level dependency. Default to dark (matches TaoQ brand). User can toggle via UI control, preference persists across sessions via localStorage.

**Alternatives considered**:
- `darkMode: "media"` (OS preference) — rejected: TaoQ brand is dark-first, should default to dark regardless of OS setting.
- CSS custom properties only — rejected: Tailwind class strategy integrates better with shadcn/ui components.
