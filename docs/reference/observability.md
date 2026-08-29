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
