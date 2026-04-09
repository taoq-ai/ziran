# Data Model: v0.8 — Runtime Bridge and Positioning

**Branch**: `011-runtime-bridge-v0-8` | **Date**: 2026-04-09

## Extended Entities (existing)

### DangerousChain (domain/entities/capability.py)

Existing dataclass extended with optional trace-evidence fields.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tools` | `list[str]` | — | Ordered tool names in the chain |
| `risk_level` | `str` | — | "critical" / "high" / "medium" / "low" |
| `vulnerability_type` | `str` | — | Category of the vulnerability |
| `exploit_description` | `str` | — | Human-readable exploit narrative |
| `remediation` | `str` | — | Recommended fix |
| `graph_path` | `list[str]` | — | Full graph path |
| `risk_score` | `float` | `0.0` | Betweenness-centrality-based score |
| `chain_type` | `str` | `"direct"` | "direct" / "indirect" / "cycle" |
| **`observed_in_production`** | **`bool`** | **`False`** | **NEW: True if seen in traces** |
| **`first_seen`** | **`datetime \| None`** | **`None`** | **NEW: Earliest trace timestamp** |
| **`last_seen`** | **`datetime \| None`** | **`None`** | **NEW: Latest trace timestamp** |
| **`occurrence_count`** | **`int`** | **`0`** | **NEW: Times observed** |
| **`trace_source`** | **`str \| None`** | **`None`** | **NEW: "otel" / "langfuse"** |

### CampaignResult (domain/entities/phase.py)

Existing Pydantic model extended with source discriminator.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| ... (all existing fields) | ... | ... | Unchanged |
| **`source`** | **`str`** | **`"scan"`** | **NEW: "scan" / "trace-analysis"** |

---

## New Entities

### PolicyFormat (domain/entities/policy.py)

Enum of supported guardrail target formats.

| Value | Description |
|-------|-------------|
| `REGO` | OPA / Rego deny rules |
| `CEDAR` | AWS Cedar forbid policies |
| `COLANG` | NeMo Guardrails Colang 2.0 flows |
| `INVARIANT` | Invariant Labs policy DSL rules |

### GuardrailPolicy (domain/entities/policy.py)

Pydantic model representing a single generated policy artifact.

| Field | Type | Description |
|-------|------|-------------|
| `finding_id` | `str` | Ziran finding ID this policy was generated from |
| `format` | `PolicyFormat` | Target format |
| `content` | `str` | Rendered policy text (ready to write to file) |
| `tool_chain` | `list[str]` | Tool names in the denied chain |
| `severity` | `str` | Severity of the originating finding |
| `skipped` | `bool` | True if the chain couldn't be expressed in this format |
| `skip_reason` | `str \| None` | Explanation if skipped |

### TraceSession (domain/entities/trace.py)

Pydantic model representing a reconstructed agent session from traces.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `str` | Trace/session identifier |
| `agent_name` | `str` | Agent/service name |
| `tool_calls` | `list[ToolCallEvent]` | Ordered tool invocations |
| `start_time` | `datetime` | Session start |
| `end_time` | `datetime` | Session end |
| `source` | `str` | "otel" / "langfuse" |
| `metadata` | `dict[str, Any]` | Additional trace metadata |

### ToolCallEvent (domain/entities/trace.py)

Pydantic model representing a single tool invocation within a trace.

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | `str` | Name of the invoked tool |
| `arguments` | `dict[str, Any]` | Tool call arguments |
| `result` | `Any \| None` | Tool call result (if captured) |
| `timestamp` | `datetime` | Invocation time |
| `span_id` | `str \| None` | OTel span ID or Langfuse observation ID |
| `parent_span_id` | `str \| None` | Parent span for hierarchy |

### ManifestSnapshot (domain/entities/registry.py)

Pydantic model representing a stored MCP server manifest.

| Field | Type | Description |
|-------|------|-------------|
| `server_name` | `str` | MCP server identifier |
| `fetched_at` | `datetime` | When this snapshot was taken |
| `tools` | `list[ToolDescriptor]` | Tool list with names, descriptions, schemas |
| `resources` | `list[dict[str, Any]]` | Resource URIs |
| `prompts` | `list[dict[str, Any]]` | Prompt metadata |
| `raw_manifest` | `dict[str, Any]` | Full original manifest for future diff fields |

### ToolDescriptor (domain/entities/registry.py)

Pydantic model for a tool within an MCP manifest.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Tool name |
| `description` | `str` | Tool description |
| `parameters` | `dict[str, Any]` | JSON Schema of input parameters |
| `permissions` | `list[str]` | Declared permissions / capabilities |

### DriftFinding (domain/entities/registry.py)

Pydantic model for a detected manifest change.

| Field | Type | Description |
|-------|------|-------------|
| `server_name` | `str` | MCP server that drifted |
| `drift_type` | `str` | "tool_added" / "tool_removed" / "description_changed" / "schema_changed" / "permission_changed" / "typosquat" |
| `severity` | `str` | "critical" / "high" / "medium" / "low" |
| `tool_name` | `str \| None` | Affected tool (if applicable) |
| `field` | `str \| None` | Affected field (e.g., "description") |
| `previous_value` | `str \| None` | Before-change value |
| `current_value` | `str \| None` | After-change value |
| `suspected_canonical` | `str \| None` | For typosquat: the real name |
| `message` | `str` | Human-readable finding description |

### RegistryConfig (domain/entities/registry.py)

Pydantic model for the watcher's YAML configuration.

| Field | Type | Description |
|-------|------|-------------|
| `servers` | `list[ServerEntry]` | MCP servers to watch |
| `allowlist` | `list[str]` | Known-good names for typosquatting check |
| `exemptions` | `list[str]` | Names explicitly excluded from typosquat check |
| `snapshot_dir` | `Path \| None` | Override for snapshot storage location |

### ServerEntry (domain/entities/registry.py)

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Server identifier |
| `url` | `str` | MCP server endpoint URL |
| `transport` | `str` | "stdio" / "sse" / "streamable-http" |

---

## Domain Ports (ABCs)

### PolicyRenderer (domain/ports/policy_renderer.py)

```
class PolicyRenderer(ABC):
    format: PolicyFormat
    def render(finding: DangerousChain) -> GuardrailPolicy
```

### TraceIngestor (domain/ports/trace_ingestor.py)

```
class TraceIngestor(ABC):
    async def ingest(source: Path | str) -> list[TraceSession]
```

### SnapshotStore (domain/ports/snapshot_store.py)

```
class SnapshotStore(ABC):
    def load(server_name: str) -> ManifestSnapshot | None
    def save(server_name: str, snapshot: ManifestSnapshot) -> None
```

---

## Entity Relationships

```
CampaignResult ──contains──► DangerousChain ──generates──► GuardrailPolicy
                                    ▲
TraceSession ──contains──► ToolCallEvent ──analyzed-by──► ToolChainAnalyzer ──produces──┘

RegistryConfig ──lists──► ServerEntry ──fetched-as──► ManifestSnapshot
ManifestSnapshot ──diffed──► DriftFinding

DangerousChain ──matched-by──► ChainPatternRegistry (existing, unchanged)
```
