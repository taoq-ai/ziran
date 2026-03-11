# Example 22 — OpenTelemetry Tracing

Demonstrates ZIRAN's OpenTelemetry instrumentation for observability
into security scan campaigns.

## What this shows

- Enabling OTel tracing via the `--otel` CLI flag
- Span hierarchy: campaign → phase → attack → detection
- Console span exporter for local debugging
- OTLP exporter for production (Jaeger, Grafana Tempo, etc.)

## Prerequisites

```bash
pip install "ziran[otel]"
# or for OTLP export:
pip install "ziran[otel]" opentelemetry-exporter-otlp
```

## Quick Start — Console Exporter

The simplest way to see spans is with the built-in console exporter:

```bash
# Scan with OTel tracing to console
ziran scan http://localhost:8000 --otel
```

This prints span details (name, attributes, duration) to stderr after
each span completes.

## OTLP Export — Jaeger / Grafana Tempo

For production observability, use the OTLP exporter with environment
variables:

```bash
# Start Jaeger (all-in-one)
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Scan with OTLP export
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
OTEL_SERVICE_NAME=ziran \
  python otel_otlp_scan.py http://localhost:8000

# View traces in Jaeger UI
open http://localhost:16686
```

## Programmatic Usage

See `otel_console_scan.py` for console export and `otel_otlp_scan.py`
for OTLP export using the Python API directly.

## Span Hierarchy

```
ziran.campaign
  ├── ziran.phase (per phase)
  │   └── ziran.attack (per attack)
  │       └── ziran.detection
  └── ziran.chain_analysis
```

### Key Attributes

| Span | Attributes |
|------|-----------|
| `ziran.campaign` | campaign_id, phase_count, coverage, strategy |
| `ziran.phase` | phase.name, phase.index, vulnerabilities, trust_score |
| `ziran.attack` | attack.id, attack.name, attack.category, attack.severity |
| `ziran.detection` | detection.successful, detection.score |
| `ziran.chain_analysis` | chain_count, chain_critical |

### Events

- `vulnerability_found` on `ziran.attack` — emitted when an attack succeeds
