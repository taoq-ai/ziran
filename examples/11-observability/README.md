# Example 11 — Observability (Prometheus metrics)

Demonstrates ZIRAN's OpenTelemetry metrics export and a ready-to-import Grafana
dashboard for campaign, attack, and phase metrics.

## What this shows

- Enabling metrics via the `--metrics-port` (Prometheus pull) and
  `--metrics-endpoint` (OTLP push) CLI flags
- The nine ZIRAN instruments (counters, gauges, histograms) and their labels
- A sample Grafana dashboard (`ziran-metrics-dashboard.json`)

## Prerequisites

```bash
pip install "ziran[otel]"
```

## Pull endpoint (Prometheus scrapes ZIRAN)

```bash
ziran scan --target ./target.yaml --metrics-port 9464
```

Point Prometheus at `http://<host>:9464/metrics`:

```yaml
scrape_configs:
  - job_name: ziran
    static_configs:
      - targets: ["localhost:9464"]
```

## Push endpoint (ZIRAN pushes to an OTel collector)

```bash
ziran scan --target ./target.yaml --metrics-endpoint http://collector:4318
```

The collector re-exports to Prometheus (or any backend). Both flags may be
combined.

## Grafana dashboard

Import `ziran-metrics-dashboard.json` in Grafana (Dashboards -> New -> Import)
and select your Prometheus data source. Panels: attack success rate, attacks
executed by phase, attack-duration p95, refusal rate by provider, tokens per
phase, and active concurrency.

See `docs/reference/observability.md` for the full metric and label reference.
