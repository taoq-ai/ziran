# OpenTelemetry Tracing

ZIRAN integrates with [OpenTelemetry](https://opentelemetry.io/) to provide distributed tracing for security scan campaigns. This enables full observability into campaign execution, phase timing, attack performance, and detection results.

## Overview

When enabled, ZIRAN creates spans for:

- **Campaign** — top-level span covering the entire scan
- **Phases** — one span per scan phase (reconnaissance, exploitation, etc.)
- **Attacks** — one span per attack vector executed
- **Detection** — spans for the detector pipeline evaluation
- **Chain Analysis** — spans for tool chain analysis

All spans carry structured attributes (campaign ID, attack category, severity, trust score, etc.) that enable filtering and aggregation in your observability backend.

## Installation

OTel support is an optional dependency:

```bash
pip install "ziran[otel]"
```

For OTLP export (Jaeger, Grafana Tempo, Datadog, etc.):

```bash
pip install "ziran[otel]" opentelemetry-exporter-otlp
```

## Quick Start — CLI

The `--otel` flag enables tracing with a console exporter:

```bash
ziran scan http://localhost:8000 --otel
```

Spans are printed to stderr as they complete.

## Programmatic Usage

### Console Exporter

```python
import asyncio
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.domain.entities.phase import CoverageLevel
from ziran.infrastructure.adapters.http_agent import HttpAgentAdapter
from ziran.infrastructure.telemetry.tracing import configure_console_exporter

configure_console_exporter()

adapter = HttpAgentAdapter(base_url="http://localhost:8000")
scanner = AgentScanner(adapter=adapter)
result = asyncio.run(scanner.run_campaign(coverage=CoverageLevel.QUICK))
```

### OTLP Exporter (Jaeger, Grafana Tempo)

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

resource = Resource.create({"service.name": "ziran"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)

# Now run ZIRAN — spans will be sent to the OTLP endpoint
```

## Span Hierarchy

```
ziran.campaign
  ├── ziran.phase (per phase)
  │   └── ziran.attack (per attack)
  │       └── ziran.detection
  └── ziran.chain_analysis
```

## Span Attributes

### `ziran.campaign`

| Attribute | Type | Description |
|-----------|------|-------------|
| `ziran.campaign.id` | string | Campaign identifier |
| `ziran.campaign.phase_count` | int | Number of phases to execute |
| `ziran.campaign.coverage` | string | Coverage level (quick/standard/thorough) |
| `ziran.campaign.strategy` | string | Campaign strategy name |
| `ziran.campaign.total_vulnerabilities` | int | Final vulnerability count |
| `ziran.campaign.trust_score` | float | Final trust score (0.0–1.0) |
| `ziran.campaign.duration_seconds` | float | Total campaign duration |

### `ziran.phase`

| Attribute | Type | Description |
|-----------|------|-------------|
| `ziran.phase.name` | string | Phase name (e.g., EXPLOITATION) |
| `ziran.phase.index` | int | Phase execution order |
| `ziran.phase.vulnerabilities` | int | Vulnerabilities found in phase |
| `ziran.phase.trust_score` | float | Phase trust score |
| `ziran.phase.attacks_executed` | int | Number of attacks run |

### `ziran.attack`

| Attribute | Type | Description |
|-----------|------|-------------|
| `ziran.attack.id` | string | Attack vector ID |
| `ziran.attack.name` | string | Attack vector name |
| `ziran.attack.category` | string | Attack category |
| `ziran.attack.severity` | string | Severity level |
| `ziran.attack.tactic` | string | Tactic type (single, crescendo, etc.) |

### `ziran.detection`

| Attribute | Type | Description |
|-----------|------|-------------|
| `ziran.detection.successful` | bool | Whether attack was detected as successful |
| `ziran.detection.score` | float | Detection confidence score |

### `ziran.chain_analysis`

| Attribute | Type | Description |
|-----------|------|-------------|
| `ziran.chain_analysis.chain_count` | int | Number of dangerous chains found |
| `ziran.chain_analysis.chain_critical` | int | Number of critical-risk chains |

## Events

- **`vulnerability_found`** — emitted on `ziran.attack` spans when an attack succeeds. Includes `vector_id`, `vector_name`, `category`, and `severity` attributes.

## Zero Overhead When Disabled

When `opentelemetry-api` is not installed, ZIRAN uses a no-op tracer that discards all span operations with zero overhead. No conditional imports are needed in instrumented code.

## CI/CD Integration

Use `--otel` with an OTLP endpoint in CI for security scan observability:

```yaml
# .github/workflows/security.yml
- name: Run security scan with tracing
  env:
    OTEL_EXPORTER_OTLP_ENDPOINT: ${{ secrets.OTEL_ENDPOINT }}
    OTEL_SERVICE_NAME: my-agent-security
  run: |
    ziran scan ${{ env.AGENT_URL }} --otel --format json > results.json
```

## Example

See `examples/22-otel-tracing/` for complete working examples with both console and OTLP exporters.
