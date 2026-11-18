# API Contracts: Findings, Compliance & Export

**Date**: 2026-03-24

## Findings Endpoints

### GET /api/findings

List findings with filtering, search, and pagination.

**Query Parameters**:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| run_id | UUID | null | Filter by source run |
| severity | string | null | Filter: critical, high, medium, low, info |
| status | string | null | Filter: open, fixed, false_positive, ignored |
| category | string | null | Filter by attack category |
| owasp | string | null | Filter by OWASP category (LLM01–LLM10) |
| target | string | null | Filter by target agent |
| search | string | null | Text search across title, description, vector_name |
| sort | string | "-created_at" | Sort field (prefix `-` for desc). Allowed: created_at, severity, status, category |
| limit | int | 25 | Page size (max 100) |
| offset | int | 0 | Pagination offset |

**Response 200**:
```json
{
  "items": [FindingSummary],
  "total": 150,
  "limit": 25,
  "offset": 0
}
```

**FindingSummary**:
```json
{
  "id": "uuid",
  "run_id": "uuid",
  "vector_name": "string",
  "category": "string",
  "severity": "critical|high|medium|low|info",
  "owasp_category": "LLM01|...|LLM10|null",
  "target_agent": "string",
  "status": "open|fixed|false_positive|ignored",
  "title": "string",
  "created_at": "2026-03-24T12:00:00Z"
}
```

---

### GET /api/findings/{id}

Get full finding detail.

**Response 200** — `FindingDetail`:
```json
{
  "id": "uuid",
  "run_id": "uuid",
  "fingerprint": "string",
  "vector_id": "string",
  "vector_name": "string",
  "category": "string",
  "severity": "critical|high|medium|low|info",
  "owasp_category": "LLM01|...|LLM10|null",
  "target_agent": "string",
  "status": "open|fixed|false_positive|ignored",
  "status_changed_at": "datetime|null",
  "title": "string",
  "description": "string|null",
  "remediation": "string|null",
  "prompt_used": "string|null",
  "agent_response": "string|null",
  "evidence": {},
  "detection_metadata": {},
  "business_impact": ["string"],
  "compliance_mappings": [
    {"framework": "owasp_llm", "control_id": "LLM01", "control_name": "Prompt Injection"}
  ],
  "created_at": "datetime"
}
```

**Response 404**: `{"detail": "Finding not found"}`

---

### PATCH /api/findings/{id}/status

Update finding status.

**Request Body**:
```json
{
  "status": "fixed|false_positive|ignored|open"
}
```

**Response 200**: Updated `FindingSummary`

**Response 404**: `{"detail": "Finding not found"}`
**Response 422**: `{"detail": "Invalid status value"}`

---

### POST /api/findings/bulk-status

Bulk update finding statuses.

**Request Body**:
```json
{
  "finding_ids": ["uuid", "uuid"],
  "status": "fixed|false_positive|ignored|open"
}
```

**Response 200**:
```json
{
  "updated": 5,
  "failed": 0
}
```

**Response 422**: `{"detail": "finding_ids must not be empty"}`

---

### GET /api/findings/stats

Aggregate finding statistics.

**Query Parameters**: Same filters as GET /api/findings (excluding sort, limit, offset).

**Response 200**:
```json
{
  "total": 150,
  "by_severity": {"critical": 5, "high": 20, "medium": 50, "low": 60, "info": 15},
  "by_status": {"open": 100, "fixed": 30, "false_positive": 10, "ignored": 10},
  "by_category": {"prompt_injection": 40, "tool_manipulation": 30, ...},
  "by_owasp": {"LLM01": 25, "LLM02": 10, ...}
}
```

---

## Compliance Endpoints

### GET /api/compliance/owasp

OWASP LLM Top 10 coverage matrix data.

**Query Parameters**:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| run_id | UUID | null | Scope to a specific run (null = all runs) |

**Response 200**:
```json
{
  "categories": [
    {
      "control_id": "LLM01",
      "control_name": "Prompt Injection",
      "description": "string",
      "finding_count": 25,
      "by_severity": {"critical": 2, "high": 5, "medium": 10, "low": 8, "info": 0},
      "status": "critical|warning|pass|not_tested"
    }
  ],
  "summary": {
    "total_categories": 10,
    "tested": 7,
    "not_tested": 3,
    "with_critical": 2,
    "with_findings": 5
  }
}
```

**Status logic**:
- `critical`: has critical or high severity findings
- `warning`: has medium or low severity findings only
- `pass`: tested (has compliance mappings) but no open findings
- `not_tested`: no findings mapped to this category

---

## Export Endpoints

### GET /api/export/findings.csv

Export findings as CSV with current filters.

**Query Parameters**: Same as GET /api/findings (excluding sort, limit, offset).

**Response 200**: `Content-Type: text/csv`, `Content-Disposition: attachment; filename="findings.csv"`

CSV columns: id, severity, title, category, owasp_category, target_agent, status, vector_name, created_at

---

### GET /api/export/findings.json

Export findings as JSON.

**Query Parameters**: Same as GET /api/findings (excluding limit, offset — returns all).

**Response 200**: `Content-Type: application/json`, `Content-Disposition: attachment; filename="findings.json"`

Body: Array of FindingSummary objects.

---

### GET /api/export/run/{id}.yaml

Export run configuration as YAML.

**Response 200**: `Content-Type: application/x-yaml`, `Content-Disposition: attachment; filename="run-{id}.yaml"`

**Response 404**: `{"detail": "Run not found"}`

---

### GET /api/export/run/{id}.md

Export run summary as Markdown report.

**Response 200**: `Content-Type: text/markdown`, `Content-Disposition: attachment; filename="run-{id}.md"`

Report sections: Title, Summary stats, Findings table (sorted by severity), OWASP coverage, Configuration.

**Response 404**: `{"detail": "Run not found"}`
