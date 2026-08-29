# Observability

ZIRAN emits structured logs through [structlog](https://www.structlog.org/). Logs render either
as human-readable Rich text (for interactive terminals) or as one JSON object per line (for
machine ingestion into Elastic, Datadog, Splunk, or any log shipper).

## Choosing a format

The root CLI accepts `--log-format`:

```
ziran --log-format json scan --target ./target.yaml
ziran --log-format text scan --target ./target.yaml
```

When `--log-format` is omitted, the format is auto-detected from standard error:

- **TTY** (interactive terminal) -> `text` (Rich output).
- **Non-TTY** (piped, redirected, CI) -> `json`.

So a plain `ziran scan ... 2> run.log` in CI produces JSON without any extra flag, while running
the same command in a terminal stays human-readable.

Logs are written to standard error. `--log-file PATH` additionally writes every record as JSON to a
file, regardless of the console format. `--verbose` / `-v` raises the level to `DEBUG`.

## JSON line fields

Every JSON log line carries these base fields:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO-8601 UTC timestamp. |
| `level` | Log level (`debug`, `info`, `warning`, `error`, `critical`). |
| `logger` | Logger name (e.g. `ziran.application.agent_scanner.scanner`). |
| `event` | The event name (a short identifier such as `campaign_started`). |

During a scan campaign, context fields are merged in automatically wherever the scanner has bound
them:

| Field | Bound by | Present on |
|-------|----------|------------|
| `campaign_id` | the scanner, once per campaign | all campaign-scoped lines |
| `phase` | the phase executor, per phase | phase and attack lines |
| `vector_id` | the attack executor, per attack | attack-scoped lines |

Any additional keyword fields passed at the call site (for example `error`, `duration_seconds`,
`trust_score`) appear alongside these.

### Example

```json
{"timestamp": "2026-08-29T10:15:04.123456Z", "level": "info", "logger": "ziran.application.agent_scanner.scanner", "event": "campaign_started", "campaign_id": "campaign_1756462504", "phase_count": 8, "coverage": "standard", "strategy": "FixedStrategy", "streaming": false}
{"timestamp": "2026-08-29T10:15:06.882012Z", "level": "warning", "logger": "ziran.application.agent_scanner.attack_executor", "event": "prompt_timed_out", "campaign_id": "campaign_1756462504", "phase": "vulnerability_discovery", "vector_id": "sql_injection_basic"}
```

## Ingestion

Because each line is a self-contained JSON object, standard tooling works directly:

```bash
# Every failed attack in a run
ziran --log-format json scan --target ./target.yaml 2> run.log
jq 'select(.event | endswith("_failed"))' run.log

# Ship to a collector
ziran --log-format json scan --target ./target.yaml 2>&1 | vector
```

## Interop with plain logging

Third-party libraries and code that use the standard library `logging.getLogger()` still render
through the same pipeline, so their records appear in the chosen format too. Application code uses
`get_logger()` from `ziran.infrastructure.logging.logger` and emits structured events:

```python
from ziran.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)
logger.info("attack_failed", vector_id=vector_id, error=str(exc))
```

Context is bound with the helpers in `ziran.infrastructure.logging.context`
(`bind_campaign`, `bind_phase`, `bind_vector`, `clear_context`), which wrap
`structlog.contextvars` so fields flow into every log line within the current async context.
ZIRAN emits OpenTelemetry signals so security campaigns can be monitored like
any other production workload. All instrumentation lives behind the optional
`otel` extra and falls back to zero-overhead no-ops when it is not installed.

```bash
pip install "ziran[otel]"
```

## Metrics (Prometheus-compatible)

ZIRAN exports campaign, attack, and phase metrics over OpenTelemetry. Export is
Prometheus-compatible in two modes, which may be combined:

- **Pull** — `--metrics-port 9464` starts a `/metrics` endpoint that Prometheus
  scrapes directly.
- **Push** — `--metrics-endpoint http://collector:4318` sends metrics over
  OTLP/HTTP to an OpenTelemetry Collector, which re-exports to any backend.

```bash
# Prometheus pull endpoint
ziran scan --target ./target.yaml --metrics-port 9464

# OTLP push to a collector
ziran scan --target ./target.yaml --metrics-endpoint http://collector:4318
```

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: ziran
    static_configs:
      - targets: ["localhost:9464"]
```

### Instruments

Metric names use OpenTelemetry dotted notation; the Prometheus exporter maps
dots to underscores and appends `_total` to counters.

| OTel name | Prometheus name | Type | Labels |
| --- | --- | --- | --- |
| `ziran.campaigns.started` | `ziran_campaigns_started_total` | counter | `campaign_id`, `coverage_level` |
| `ziran.campaigns.completed` | `ziran_campaigns_completed_total` | counter | `campaign_id`, `coverage_level` |
| `ziran.attacks.executed` | `ziran_attacks_executed_total` | counter | `phase`, `vector_id`, `provider`, `coverage_level` |
| `ziran.attacks.succeeded` | `ziran_attacks_succeeded_total` | counter | `phase`, `vector_id`, `provider`, `coverage_level` |
| `ziran.attacks.refused` | `ziran_attacks_refused_total` | counter | `phase`, `vector_id`, `provider`, `coverage_level` |
| `ziran.campaign.tokens_per_phase` | `ziran_campaign_tokens_per_phase` | gauge | `phase`, `coverage_level` |
| `ziran.phase.active_concurrent` | `ziran_phase_active_concurrent` | gauge | `phase` |
| `ziran.attack.duration_seconds` | `ziran_attack_duration_seconds` | histogram | `phase`, `vector_id`, `provider`, `coverage_level` |
| `ziran.phase.duration_seconds` | `ziran_phase_duration_seconds` | histogram | `phase`, `coverage_level` |

### Labels and cardinality

- `campaign_id` — one series per run; confined to the campaign counters.
- `phase` — scan phase (`reconnaissance`, `exploitation`, ...).
- `vector_id` — attack-vector id. High cardinality, so it appears **only** on
  attack-level instruments; phase and campaign series stay low-cardinality.
- `provider` — target adapter family (e.g. `anthropic`, `langchain`), derived
  from the adapter class name.
- `coverage_level` — the scan's coverage setting (`essential`, `standard`,
  `comprehensive`).

`refused` counts attacks where the agent responded but the attack did not
succeed (a defended prompt), distinct from errors/timeouts where no response
came back.

### Example PromQL

```promql
# Attack success rate over 5m
sum(rate(ziran_attacks_succeeded_total[5m]))
  / clamp_min(sum(rate(ziran_attacks_executed_total[5m])), 1)

# p95 attack duration by phase
histogram_quantile(0.95,
  sum by (le, phase) (rate(ziran_attack_duration_seconds_bucket[5m])))

# Per-provider refusal rate
sum by (provider) (rate(ziran_attacks_refused_total[5m]))
  / clamp_min(sum by (provider) (rate(ziran_attacks_executed_total[5m])), 1)
```

### Grafana dashboard

A ready-to-import dashboard ships at
`examples/11-observability/ziran-metrics-dashboard.json`. In Grafana choose
Dashboards -> New -> Import, upload the JSON, and select your Prometheus data
source.
