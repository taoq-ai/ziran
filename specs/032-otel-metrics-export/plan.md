# Implementation Plan: OTel metrics export (Prometheus-compatible)

## Technical context
- Python 3.11+ (CI 3.11/3.12/3.13). Reuses OpenTelemetry (already an `otel` extra for tracing).
- New optional deps in the `otel` extra: `opentelemetry-exporter-prometheus` (pull, pulls in
  `prometheus_client`) and `opentelemetry-exporter-otlp-proto-http` (push). API/SDK floor bumped to
  `>=1.23` for the synchronous `create_gauge` API. Core install unaffected.

## Design
1. **`ziran/infrastructure/telemetry/metrics.py`** — mirrors `tracing.py`:
   - `_HAS_OTEL` import guard; module global `_METRICS: _Instruments | None = None`.
   - `_Instruments(meter)` creates the nine instruments (FR-003) and holds an `inflight: dict[str,int]`
     for the active-concurrent gauge.
   - `configure_metrics(*, endpoint=None, port=None)`: build metric readers — `PrometheusMetricReader`
     + `prometheus_client.start_http_server(port)` for pull; `PeriodicExportingMetricReader(OTLPMetricExporter(endpoint))`
     for push — attach to a `MeterProvider`, take a meter from it, and populate `_METRICS`.
   - Recording helpers, each a no-op when `_METRICS is None`:
     `campaign_started/campaign_completed(campaign_id, coverage_level)`;
     `attack_started(phase)` (bumps concurrency gauge);
     `record_attack(*, phase, vector_id, provider, coverage_level, successful, refused, duration_seconds)`
     (executed/succeeded/refused counters + duration histogram + decrements concurrency);
     `record_phase(*, phase, coverage_level, duration_seconds, tokens)` (phase histogram + tokens gauge).
   - `get_meter(name)` + `reset_metrics()` (test teardown / reconfigure).
2. **`ziran/application/agent_scanner/campaign_telemetry.py`** (new sub-module, < 400 lines) —
   extract the campaign span lifecycle out of `scanner.py` so scanner shrinks while gaining metrics:
   `start_campaign_span(...) -> span` (starts the OTel span AND `metrics.campaign_started`);
   `finish_campaign_span(span, *, ...)` (sets span attrs, ends span, AND `metrics.campaign_completed`).
   Scanner replaces its two inline span blocks with these calls (net line reduction → stays <= 750).
3. **`ziran/application/agent_scanner/phase_executor.py`** — derive `provider` from the executor's
   adapter (bounded-cardinality class-name label); wrap each attack in `attack_started` +
   `record_attack` with `time.perf_counter()` duration; `refused := not successful and agent_response is not None`;
   record `record_phase` at phase finalize alongside the existing span.
4. **`ziran/application/agent_scanner/attack_executor.py`** — expose `self.provider`
   (`type(adapter).__name__` normalized) for the phase executor to label with.
5. **CLI** (`ziran/interfaces/cli/main.py`) — add `--metrics-endpoint` / `--metrics-port` options
   to `scan`; call `metrics.configure_metrics(...)` when either is set (alongside the existing `--otel`).
6. **Assets** — `examples/11-observability/` Grafana dashboard JSON + README;
   `docs/reference/observability.md` self-contained metrics section (item C owns the tracing/logging
   parts on its own branch — write metrics as an appendable section for clean concatenation).

## Cardinality note
`vector_id` is high-cardinality and lands only on attack-level instruments (FR-004). `campaign_id`
is per-run and confined to campaign counters. Phase/duration/token series stay low-cardinality.

## Phases
- P1: `metrics.py` module + unit tests (no-op path, configure wiring with mocked exporters, label sets).
- P2: `campaign_telemetry.py` extraction + scanner rewire; phase/attack instrumentation + unit tests.
- P3: CLI flags + wiring test.
- P4: live Prometheus scrape integration test; Grafana dashboard JSON; docs section.
- Gate: ruff, ruff format, mypy strict, pytest --cov >= 85%; scanner size test stays green.
