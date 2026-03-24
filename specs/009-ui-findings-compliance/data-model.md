# Data Model: UI Batch 2 — Findings Management, Compliance & Design System

**Date**: 2026-03-24

## Entity Relationship Diagram

```text
┌──────────┐     1:N     ┌──────────────┐     1:N     ┌─────────────────────┐
│   Run     │────────────►│   Finding     │────────────►│  ComplianceMapping   │
│ (existing)│             │ (new)         │             │  (new)              │
└──────────┘             └──────────────┘             └─────────────────────┘
                               │
                               │ N:1 (via fingerprint dedup)
                               ▼
                         ┌──────────────┐
                         │  ExportJob    │
                         │  (new, future)│
                         └──────────────┘
```

## Entities

### Finding (NEW)

Denormalized from `Run.result_json.attack_results[]` for queryable filtering and status tracking.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK, auto-generated | Unique finding identifier |
| run_id | UUID | FK → runs.id, NOT NULL | Source scan run |
| fingerprint | VARCHAR(64) | NOT NULL, INDEX | SHA256 hash for dedup: `sha256(target_agent + vector_id + category)` |
| vector_id | VARCHAR(255) | NOT NULL | Attack vector identifier from YAML definition |
| vector_name | VARCHAR(255) | NOT NULL | Human-readable attack name |
| category | VARCHAR(50) | NOT NULL, INDEX | Attack category (prompt_injection, tool_manipulation, etc.) |
| severity | VARCHAR(10) | NOT NULL, INDEX | critical / high / medium / low / info |
| owasp_category | VARCHAR(10) | NULL, INDEX | Primary OWASP LLM category (LLM01–LLM10) |
| target_agent | VARCHAR(255) | NOT NULL, INDEX | Target agent URL/identifier |
| status | VARCHAR(20) | NOT NULL, DEFAULT 'open', INDEX | open / fixed / false_positive / ignored |
| status_changed_at | TIMESTAMP | NULL | When status was last changed |
| title | TEXT | NOT NULL | Finding title (derived from vector_name + category) |
| description | TEXT | NULL | Detailed description of the vulnerability |
| remediation | TEXT | NULL | Suggested remediation guidance |
| prompt_used | TEXT | NULL | Attack prompt that triggered the finding |
| agent_response | TEXT | NULL | Agent's response to the attack |
| evidence | JSONB | NULL | Detection evidence dict |
| detection_metadata | JSONB | NULL | Additional detection metadata (encoding, quality_score, etc.) |
| business_impact | JSONB | NULL | List of BusinessImpact values |
| created_at | TIMESTAMP | NOT NULL, DEFAULT now() | When finding was first detected |

**Indexes**:
- `ix_findings_fingerprint` on `fingerprint` (for dedup lookups)
- `ix_findings_run_id` on `run_id` (for per-run queries)
- `ix_findings_severity` on `severity` (for filtering)
- `ix_findings_status` on `status` (for filtering)
- `ix_findings_category` on `category` (for filtering)
- `ix_findings_owasp` on `owasp_category` (for compliance queries)
- `ix_findings_target` on `target_agent` (for per-target queries)
- Composite: `ix_findings_severity_status` on `(severity, status)` (common filter combo)

**Constraints**:
- `severity` CHECK IN ('critical', 'high', 'medium', 'low', 'info')
- `status` CHECK IN ('open', 'fixed', 'false_positive', 'ignored')

---

### ComplianceMapping (NEW)

Links a finding to one or more compliance framework controls.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK, auto-generated | Unique mapping identifier |
| finding_id | UUID | FK → findings.id, NOT NULL, ON DELETE CASCADE | Parent finding |
| framework | VARCHAR(50) | NOT NULL | Compliance framework name (e.g., 'owasp_llm') |
| control_id | VARCHAR(20) | NOT NULL | Framework control ID (e.g., 'LLM01') |
| control_name | VARCHAR(255) | NOT NULL | Human-readable control name |

**Indexes**:
- `ix_compliance_finding` on `finding_id`
- `ix_compliance_framework_control` on `(framework, control_id)` (for aggregation)

**Constraints**:
- UNIQUE on `(finding_id, framework, control_id)` — one mapping per finding per control

---

### ExportJob (NEW — schema only, for future async support)

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK, auto-generated | Unique job identifier |
| format | VARCHAR(10) | NOT NULL | csv / json / yaml / markdown |
| filters_json | JSONB | NULL | Applied filter parameters |
| status | VARCHAR(20) | NOT NULL, DEFAULT 'pending' | pending / processing / completed / failed |
| file_path | VARCHAR(500) | NULL | Path to generated file (if completed) |
| error | TEXT | NULL | Error message (if failed) |
| created_at | TIMESTAMP | NOT NULL, DEFAULT now() | When export was requested |
| completed_at | TIMESTAMP | NULL | When export finished |

**Note**: This table is included in the migration for future use but is NOT actively used in this batch. Community exports are synchronous.

---

## State Machine: Finding Status

```text
            ┌──────────┐
  (created) │          │
  ─────────►│   Open   │
            │          │
            └────┬─────┘
                 │
        ┌────────┼────────┐
        │        │        │
        ▼        ▼        ▼
   ┌─────────┐ ┌──────────┐ ┌─────────┐
   │  Fixed  │ │  False   │ │ Ignored │
   │         │ │ Positive │ │         │
   └────┬────┘ └────┬─────┘ └────┬────┘
        │           │            │
        └───────────┼────────────┘
                    │
                    ▼
              ┌──────────┐
              │   Open   │ (can reopen)
              └──────────┘
```

All transitions are bidirectional — any status can move to any other status.

## Migration: 002_findings_schema.py

Creates tables: `findings`, `compliance_mappings`, `export_jobs`
Adds indexes and constraints as defined above.
Does NOT modify existing tables (`runs`, `phase_results`, `config_presets`).
