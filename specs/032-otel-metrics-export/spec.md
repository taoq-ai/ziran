# Feature Specification: OTel metrics export (Prometheus-compatible)

**Feature Branch**: `032-otel-metrics-export`
**Created**: 2026-08-29
**Status**: Active
**Input**: ZIRAN emits OTel spans (spec 003/022) but no metrics. Enterprise observability teams
want dashboards over time: attack success rate, tokens-per-phase, wall-clock histograms, and
per-provider throughput. Metrics are the missing half of the telemetry story. Export must be
Prometheus-compatible (pull scrape or push to an OTel collector) and stay behind the existing
`otel` extra so the core install keeps working with zero overhead.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Scrape campaign metrics from Prometheus (Priority: P1)
An observability engineer runs a scan with `--metrics-port 9464` and points Prometheus at
`http://host:9464/metrics`. The scrape returns ZIRAN campaign, attack, and phase metrics in
Prometheus text format, with labels they can slice dashboards by (phase, provider, coverage level).

**Why this priority**: The pull endpoint is the canonical Prometheus integration and needs no
extra infrastructure. It is the smallest slice that delivers a working dashboard.

**Independent Test**: Configure metrics on a free port, record a handful of instrument values,
`GET /metrics`, and assert the expected metric names and label sets appear in the exposition text.

**Acceptance Scenarios**:
1. **Given** metrics configured with a pull port, **When** the endpoint is scraped after a
   campaign records instruments, **Then** the response contains `ziran_campaigns_started_total`,
   `ziran_attacks_executed_total`, `ziran_attack_duration_seconds` (histogram) and their labels.
2. **Given** the `otel` extra is NOT installed, **When** a campaign runs without metrics flags,
   **Then** every instrumentation call is a silent no-op and the scan completes normally.

### User Story 2 — Push metrics to an OTel collector (Priority: P2)
A team already runs an OpenTelemetry Collector. They pass `--metrics-endpoint http://collector:4318`
and ZIRAN pushes metrics over OTLP/HTTP on a periodic interval; the collector re-exports them to
Prometheus (or any backend).

**Why this priority**: Push suits environments where scraping the scanner host is impractical, but
it depends on a collector being present, so it ranks below the self-contained pull path.

**Independent Test**: Call the configure function with an endpoint and assert an OTLP metric
exporter + periodic reader are wired into the meter provider (exporter constructed with the given
endpoint), without needing a live collector.

**Acceptance Scenarios**:
1. **Given** `--metrics-endpoint`, **When** metrics are configured, **Then** a periodic OTLP
   exporting reader targeting that endpoint is registered on the meter provider.
2. **Given** both `--metrics-endpoint` and `--metrics-port`, **When** configured, **Then** both a
   push reader and a pull reader are active.

### User Story 3 — Meaningful labels without cardinality blow-up (Priority: P2)
A dashboard author groups attack counters by `vector_id` to find the noisiest vectors, but expects
campaign/phase-level series to stay low-cardinality (no `vector_id` explosion on phase duration).

**Independent Test**: Assert `vector_id` is present only on attack-level instruments and absent
from campaign- and phase-level instruments.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: A `metrics.py` module MUST mirror `tracing.py`'s no-op-fallback pattern: when the OTel
  SDK is absent OR metrics were never configured, all recording calls MUST be zero-overhead no-ops.
- **FR-002**: The metrics SDK and exporters MUST live behind the existing `otel` extra; a core
  install (`pip install ziran`) MUST import and run instrumented code without them.
- **FR-003**: The module MUST define these instruments with exactly these names:
  counters `ziran.campaigns.started`, `ziran.campaigns.completed`, `ziran.attacks.executed`,
  `ziran.attacks.succeeded`, `ziran.attacks.refused`; gauges `ziran.campaign.tokens_per_phase`,
  `ziran.phase.active_concurrent`; histograms `ziran.attack.duration_seconds`,
  `ziran.phase.duration_seconds`.
- **FR-004**: Label sets MUST be: campaign counters → `campaign_id`, `coverage_level`; attack
  counters + `attack.duration_seconds` → `phase`, `vector_id`, `provider`, `coverage_level`;
  `tokens_per_phase` + `phase.duration_seconds` → `phase`, `coverage_level`;
  `phase.active_concurrent` → `phase`. `vector_id` MUST appear ONLY on attack-level instruments.
- **FR-005**: A `configure_metrics(endpoint, port)` entry point MUST wire a Prometheus pull reader
  when `port` is set and an OTLP/HTTP push reader when `endpoint` is set (both may be set).
- **FR-006**: The `scan` CLI MUST expose `--metrics-endpoint URL` (push) and `--metrics-port INT`
  (pull) and call `configure_metrics` before the campaign runs.
- **FR-007**: The campaign orchestrator MUST record campaign start/completion; the phase executor
  MUST record per-attack counters + duration, per-phase duration + tokens, and active concurrency.
- **FR-008**: `scanner.py` MUST NOT exceed its 750-line architecture-guard ceiling; campaign
  telemetry MUST be extracted into a sub-module rather than grown inline.
- **FR-009**: An integration test MUST scrape a live pull endpoint (mock Prometheus scrape) and
  assert the metrics + labels. A sample Grafana dashboard JSON MUST ship under
  `examples/11-observability/`. Docs MUST gain a self-contained metrics section in
  `docs/reference/observability.md`.

### Key Entities
- **Instrument set**: the fixed collection of counters/gauges/histograms above, created once from a
  meter when metrics are configured; `None` (no-op) otherwise.
- **Metric readers**: a Prometheus pull reader and/or an OTLP periodic push reader attached to the
  meter provider.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: Scraping the pull endpoint after a campaign returns all nine instruments with the
  labels from FR-004 in Prometheus exposition format.
- **SC-002**: With no `otel` extra and no metrics flags, a scan runs unchanged and instrumentation
  adds no observable overhead (calls short-circuit on a single `is None` check).
- **SC-003**: `scanner.py` stays at or under 750 lines; no sub-module exceeds 400 lines.
- **SC-004**: All gates pass — ruff, ruff format, mypy (strict), pytest coverage >= 85%.
