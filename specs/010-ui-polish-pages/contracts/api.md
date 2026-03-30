# API Contracts: Library & Config Presets

## Attack Library Endpoints

### GET /api/library/vectors

List all attack vectors with optional filtering.

**Query Parameters**:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| category | string | null | Filter by attack category |
| severity | string | null | Filter: critical, high, medium, low |
| phase | string | null | Filter by target phase |
| owasp | string | null | Filter by OWASP category (LLM01–LLM10) |
| search | string | null | Text search across name, description, tags |

**Response 200**:
```json
{
  "vectors": [
    {
      "id": "string",
      "name": "string",
      "category": "string",
      "severity": "critical|high|medium|low",
      "target_phase": "string",
      "description": "string",
      "tags": ["string"],
      "owasp_mapping": ["LLM01", "LLM06"],
      "prompt_count": 3,
      "protocol_filter": ["rest", "openai"]
    }
  ],
  "total": 150
}
```

### GET /api/library/vectors/{vector_id}

Get full vector detail including prompt templates.

**Response 200**:
```json
{
  "id": "string",
  "name": "string",
  "category": "string",
  "severity": "string",
  "target_phase": "string",
  "description": "string",
  "tags": ["string"],
  "references": ["string"],
  "owasp_mapping": ["string"],
  "protocol_filter": ["string"],
  "prompts": [
    {
      "template": "string",
      "variables": {"key": "value"},
      "success_indicators": ["string"],
      "failure_indicators": ["string"]
    }
  ]
}
```

### GET /api/library/stats

Aggregate library statistics.

**Response 200**:
```json
{
  "total_vectors": 150,
  "total_prompts": 450,
  "by_category": {"prompt_injection": 40, "tool_manipulation": 30},
  "by_severity": {"critical": 10, "high": 40, "medium": 60, "low": 40},
  "by_owasp": {"LLM01": 25, "LLM02": 10}
}
```

## Config Presets Endpoints

### GET /api/configs

List all config presets.

**Response 200**:
```json
[
  {
    "id": "uuid",
    "name": "string",
    "description": "string|null",
    "config": {},
    "created_at": "datetime",
    "updated_at": "datetime"
  }
]
```

### POST /api/configs

Create a new preset.

**Request Body**:
```json
{
  "name": "string (unique, required)",
  "description": "string|null",
  "config": {}
}
```

**Response 201**: Created preset object.
**Response 409**: `{"detail": "Preset name already exists"}`

### PUT /api/configs/{id}

Update an existing preset.

**Request Body**: Same as POST (partial update allowed).
**Response 200**: Updated preset object.
**Response 404**: `{"detail": "Preset not found"}`

### DELETE /api/configs/{id}

Delete a preset.

**Response 204**: No content.
**Response 404**: `{"detail": "Preset not found"}`
