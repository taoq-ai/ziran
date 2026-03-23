# Data Model: Web UI Foundation

## Entities

### Run

Represents a single security scan execution. Maps to `CampaignResult` from `ziran.domain.entities.phase`.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Campaign ID (matches `CampaignResult.campaign_id`) |
| name | String(255) | Optional | User-defined name for the run |
| target_agent | String(500) | NOT NULL | Agent identifier or target URL |
| status | String(20) | NOT NULL, default "pending" | One of: pending, running, completed, failed, cancelled |
| coverage_level | String(20) | NOT NULL, default "standard" | One of: essential, standard, comprehensive |
| strategy | String(20) | NOT NULL, default "fixed" | One of: fixed, adaptive, llm-adaptive |
| config_json | JSONB | NOT NULL | Full scan configuration (phases, encoding, etc.) |
| total_vulnerabilities | Integer | default 0 | Count of vulnerabilities found |
| critical_paths_count | Integer | default 0 | Count of critical attack paths |
| dangerous_chains_count | Integer | default 0 | Count of dangerous tool chains |
| final_trust_score | Float | Optional | Final trust score (0-1) |
| total_tokens | Integer | default 0 | Total token usage |
| result_json | JSONB | Optional | Full serialized CampaignResult |
| graph_state_json | JSONB | Optional | Graph export for vis-network |
| error | Text | Optional | Error message if status=failed |
| created_at | DateTime(tz) | NOT NULL, server default | When the run was created |
| started_at | DateTime(tz) | Optional | When the scan started executing |
| completed_at | DateTime(tz) | Optional | When the scan finished |

**Relationships**: Has many PhaseResults.

**State transitions**: pending → running → completed/failed; running → cancelled

### PhaseResult

Represents the outcome of a single phase within a run.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Auto-generated |
| run_id | UUID | FK → runs.id, NOT NULL | Parent run |
| phase | String(50) | NOT NULL | Phase name (reconnaissance, trust_building, etc.) |
| phase_index | Integer | NOT NULL | Order within the campaign (0-based) |
| success | Boolean | NOT NULL | Whether the phase succeeded |
| trust_score | Float | NOT NULL | Trust score after this phase (0-1) |
| duration_seconds | Float | NOT NULL | Phase duration |
| token_usage_json | JSONB | default {} | Token counts (prompt, completion, total) |
| vulnerabilities_found | JSONB | default [] | List of vulnerability IDs found |
| discovered_capabilities | JSONB | default [] | List of capability names |
| error | Text | Optional | Error message if phase failed |
| created_at | DateTime(tz) | NOT NULL, server default | When the record was created |

**Relationships**: Belongs to Run.

### ConfigPreset

A saved scan configuration that users can reuse.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Auto-generated |
| name | String(255) | NOT NULL, UNIQUE | Preset display name |
| description | Text | Optional | Description of what this preset tests |
| config_json | JSONB | NOT NULL | Full scan configuration |
| created_at | DateTime(tz) | NOT NULL, server default | When created |
| updated_at | DateTime(tz) | NOT NULL, auto-update | When last modified |

**Relationships**: None (independent entity).

## Indexes

- `runs`: Index on `status`, `created_at` (for dashboard queries)
- `phase_results`: Index on `run_id` (for run detail queries)
- `config_presets`: Unique index on `name`

## Migration Strategy

- Initial migration (`001_initial_schema.py`) creates all three tables
- Alembic configured programmatically (no `alembic.ini` file)
- Migrations run automatically on server startup via `alembic.command.upgrade("head")`
- Migration directory: `ziran/interfaces/web/migrations/`
