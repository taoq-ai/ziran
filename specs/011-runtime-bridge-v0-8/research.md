# Research: v0.8 — Runtime Bridge and Positioning

**Branch**: `011-runtime-bridge-v0-8` | **Date**: 2026-04-09

## R1: Policy Export Target Formats

### Decision: Support four formats with format-specific code generators

**Rationale**: Each format has fundamentally different semantics — no single template engine can cover all four. A dedicated generator per format (implementing a shared `PolicyRenderer` port) is the cleanest approach.

### Format Analysis

#### OPA Rego
- **Deny mechanism**: Populate a `deny` set; caller checks `count(deny) > 0`.
- **Sequence detection**: Manual via array indexing (`input.trace[i].tool`, `input.trace[i+1].tool`).
- **Comments**: `#` prefix.
- **Structure**: `package ziran.guardrails` → `deny[msg] { ... }` rules.
- **Fit**: Excellent — trace-level sequence rules map directly to array iteration.

#### AWS Cedar
- **Deny mechanism**: `forbid(principal, action, resource) when { ... }` statements.
- **Sequence detection**: Not native. Cedar is stateless (single authz request). The orchestrator must supply sequence context via `context.previous_tool`.
- **Comments**: `//` prefix.
- **Fit**: Adequate — Ziran will generate forbid policies that assume the runtime gateway tracks tool-call state and passes it as context attributes. A preamble comment will document this assumption.

#### NeMo Guardrails Colang 2.0
- **Deny mechanism**: `define flow` block with sequential `match ToolCall(...)` → `abort`.
- **Sequence detection**: Native via sequential `match` statements in event-driven flows.
- **Comments**: `#` prefix.
- **File extension**: `.co` files loaded by NeMo Guardrails config.
- **Fit**: Excellent — flows naturally express tool-call sequences.

#### Invariant Labs Policy DSL
- **Deny mechanism**: `raise "violation message" if: ...` with trace-pattern matching.
- **Sequence detection**: Native via `->` temporal ordering operator (`call_a -> call_b`).
- **Comments**: `#` prefix.
- **Fit**: Best of the four — purpose-built for agent trace sequence detection.

### Alternatives Considered
- **Jinja2 templates per format**: Rejected. Format semantics differ too much; templates would embed logic, defeating the purpose.
- **Single abstract policy IR then compile to targets**: Over-engineered for four formats. YAGNI — add if a fifth format arrives.

---

## R2: Trace Ingestion Formats

### Decision: Support OTel JSONL and Langfuse (file export + API pull) via adapter ports

**Rationale**: Both are confirmed required in v0.8. Different enough to warrant separate adapters behind a shared `TraceIngestor` port.

### OpenTelemetry JSONL
- **Format**: One JSON object per line, each a `ResourceSpans` batch.
- **Key fields**: `traceId` (session), `spanId`/`parentSpanId` (hierarchy), `name` (span name), `startTimeUnixNano`/`endTimeUnixNano`.
- **Tool-call identification**: `gen_ai.tool.name`, `gen_ai.tool.arguments`, `gen_ai.tool.call.id` under OpenTelemetry GenAI semantic conventions.
- **Agent grouping**: `resource.attributes[service.name]` identifies the agent; `traceId` groups spans per invocation.
- **Reconstruction strategy**: Group spans by `traceId`, filter to tool-call spans (by `gen_ai.tool.name` attribute), sort by `startTimeUnixNano`, produce ordered tool-call sequence per trace.

### Langfuse
- **File export format**: JSON with `id`, `sessionId`, `observations[]` array.
- **Observation types**: `GENERATION` (LLM call), `SPAN` (tool execution), `EVENT` (point-in-time).
- **Tool-call identification**: `SPAN` observations with `name` = tool name, `input` = arguments, `output` = result. Also visible in parent `GENERATION`'s `output.tool_calls` array.
- **Session grouping**: `sessionId` groups traces per conversation; `id` per run.
- **API pull**: `langfuse.Langfuse()` client → `fetch_traces(limit, page)` → `fetch_trace(id)` → observations. Reads `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_HOST` from env.
- **Reconstruction strategy**: Group observations by `trace.id`, filter `SPAN` type observations, sort by `startTime`, produce ordered tool-call sequence. Use `sessionId` for multi-turn grouping.

### Alternatives Considered
- **LangSmith / Phoenix support in v0.8**: Deferred — the trace ingestor port allows adding adapters later without reshaping the analyzer.
- **Generic CSV/JSON import**: Rejected — too ambiguous; dedicated adapters ensure correct field mapping.

---

## R3: Typosquatting Detection Algorithm

### Decision: Levenshtein distance + common substitution patterns

**Rationale**: Levenshtein is the standard for typosquatting detection (used by npm, PyPI advisories). Combined with character substitution rules (l/1, o/0, rn/m) it catches the most common attack patterns with minimal false positives.

### Approach
- Compare each watched MCP server name against the allowlist using normalized Levenshtein distance.
- Flag if distance ≤ 2 edits AND the name is not in the explicit exemption list.
- Additionally check common substitution patterns: character swaps (e.g., `google` → `gooogle`), homoglyphs, prefix/suffix additions.
- Severity: `high` for distance 1, `medium` for distance 2.

### Alternatives Considered
- **Phonetic similarity (Soundex/Metaphone)**: Too many false positives for technical names.
- **ML-based similarity**: Over-engineered for v0.8 scope; add later if false-positive rate warrants it.
- **Exact match only**: Too narrow; misses the whole point of typosquatting detection.

---

## R4: Snapshot Storage Format

### Decision: Local JSON files in a `.ziran/snapshots/` directory

**Rationale**: Simplest storage that satisfies the local-workspace requirement from spec assumptions. JSON is human-readable and diffable in git. SQLite adds a dependency for no v0.8 benefit.

### Structure
- One JSON file per watched MCP server: `.ziran/snapshots/{server-name}.json`
- Content: `{ "fetched_at": ISO8601, "tools": [...], "resources": [...], "prompts": [...], "raw_manifest": {...} }`
- Diff is computed in memory by comparing current fetch against stored snapshot.
- Atomic write via temp file + rename to prevent corruption on crash.

### Alternatives Considered
- **SQLite**: More query power, but adds a dependency and complexity for what is essentially a key-value store of N small manifests. Deferred.
- **Git-tracked manifests**: Interesting for audit trail, but couples watcher to git presence. Deferred.

---

## R5: Integration with Existing Pattern Engine

### Decision: Reuse `ToolChainAnalyzer` via a thin adapter that feeds externally-supplied tool-call sequences

**Rationale**: The spec assumption is confirmed — `ToolChainAnalyzer.analyze()` operates on a `ToolChainGraph` (NetworkX MultiDiGraph) that contains tool nodes and `CAN_CHAIN_TO` edges. The trace analyzer can build a temporary graph from observed sequences and pass it through the same analyzer.

### Approach
- The trace analyzer builds a temporary `AttackKnowledgeGraph` from the reconstructed tool-call sequences.
- For each session: add tool nodes, add `CAN_CHAIN_TO` edges for consecutive tool calls.
- Pass the graph to `ToolChainAnalyzer.analyze()` to get `DangerousChain` results.
- Annotate results with trace-specific metadata (timestamps, occurrence count, "observed in production" marker).
- The `ChainPatternRegistry` and `chain_patterns.yaml` are reused without modification.

### Alternatives Considered
- **Duplicate pattern matching logic for traces**: Rejected — violates DRY and would drift from scan-time patterns.
- **Modify `ToolChainAnalyzer` to accept raw sequences**: More invasive than needed. Building a graph is a few lines and preserves the existing API contract.

---

## R6: Finding Model Extension

### Decision: Add optional trace-evidence fields to the existing `DangerousChain` and `CampaignResult` models

**Rationale**: The `DangerousChain` dataclass in `domain/entities/capability.py` needs new optional fields. The `CampaignResult` in `domain/entities/phase.py` needs a new source discriminator.

### New Fields on `DangerousChain`
- `observed_in_production: bool = False`
- `first_seen: datetime | None = None`
- `last_seen: datetime | None = None`
- `occurrence_count: int = 0`
- `trace_source: str | None = None` (e.g., "otel", "langfuse")

### New Fields on `CampaignResult`
- `source: str = "scan"` (discriminator: "scan" | "trace-analysis")

All fields are optional with backward-compatible defaults, so existing scan-path code is unaffected.

---

## R7: CI Template Platforms

### Decision: Four platform templates, each mirroring the GitHub Action's coverage/gate pattern

**Rationale**: The existing GitHub Action in `.github/workflows/action-test.yml` runs `ziran ci` with `--result-file` and `--severity-threshold`. All four CI templates will invoke the same CLI command.

### Platform-Specific Notes
- **GitLab CI**: `.gitlab-ci.yml` stage; SARIF upload via GitLab Security Dashboard (artifact upload to `gl-sast-report.json`).
- **Jenkins**: Declarative pipeline stage; SARIF via Warnings Next Generation plugin (`recordIssues tool: sarif(pattern: '*.sarif')`).
- **CircleCI**: Reusable config YAML (not a full orb — lower maintenance); SARIF as artifact.
- **Azure Pipelines**: YAML task; SARIF upload to Azure DevOps Advanced Security via `PublishBuildArtifacts` + `AdvancedSecurity-Sarif@1`.

### Lint Validation
- GitLab: `python -c "import yaml; yaml.safe_load(open(...))"` in CI
- Jenkins: `jenkins-linter` or `curl -X POST <jenkins>/pipeline-model-converter/validate`
- CircleCI: `circleci config validate`
- Azure: `python -c "import yaml; yaml.safe_load(open(...))"` in CI

---

## R8: Landscape Documentation Approach

### Decision: Mermaid diagram in mkdocs page + updated README section

**Rationale**: Mermaid is already renderable by GitHub and mkdocs-material. A layered block diagram with three rows (pre-deploy, runtime, observability) is the clearest visual.

### Alternatives Considered
- **Static PNG diagram**: Harder to maintain; rejected in favor of Mermaid (text-based, versionable).
- **Interactive D3 visualization**: Over-engineered for a docs positioning page.
